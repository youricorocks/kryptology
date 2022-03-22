package participant

import (
	"crypto/elliptic"
	"github.com/btcsuite/btcd/btcec"
	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSignerSignRound_Bench(t *testing.T) {
	var (
		curve = btcec.S256()
		msg   = []byte{31: 0x01}
	)

	hash, err := core.Hash(msg, curve)
	require.NoError(t, err)

	fullRoundTest(t, curve, hash.Bytes(), k256Verifier)
}

func fullRoundTest(t *testing.T, curve elliptic.Curve, msg []byte, verify curves.EcdsaVerify) {
	fullRoundTestUseDistributed(t, curve, msg, verify, 3, 5, false)
	fullRoundTestUseDistributed(t, curve, msg, verify, 3, 5, true)
}

func fullRoundTestUseDistributed(
	t *testing.T,
	curve elliptic.Curve,
	msg []byte,
	verify curves.EcdsaVerify,
	playerMin int,
	playerCnt int,
	useDistributed bool,
) {
	pk, signers := setupSignersMap(t, curve, playerMin, playerCnt, false, verify, useDistributed)

	sk := signers[1].share.Value.Add(signers[2].share.Value).Add(signers[3].share.Value)
	_, ppk := btcec.PrivKeyFromBytes(curve, sk.Bytes())

	if ppk.X.Cmp(pk.X) != 0 || ppk.Y.Cmp(pk.Y) != 0 {
		t.Errorf("Invalid shares")
		t.FailNow()
	}

	// round 1
	signerOut, r1P2P := signRound1(t, signers, playerCnt)

	// round 2
	p2p := signRound2(t, signers, signerOut, r1P2P, playerMin, useDistributed)

	// round 3
	round3Bcast := signRound3(t, signers, p2p, playerMin)

	// round 4
	round4Bcast := signRound4(t, signers, round3Bcast, playerMin)

	// round 5
	round5Bcast, r5P2P := signRound5(t, curve, pk, signers, round4Bcast, playerMin)

	// round 6
	signRound6(t, msg, signers, round5Bcast, r5P2P, playerMin, useDistributed)
}

func signRound1(t *testing.T, signers map[uint32]*Signer, playerCnt int) (map[uint32]*Round1Bcast, map[uint32]map[uint32]*Round1P2PSend) {
	var err error

	signerOut := make(map[uint32]*Round1Bcast, playerCnt)
	r1P2P := make(map[uint32]map[uint32]*Round1P2PSend, playerCnt)

	for i, s := range signers {
		signerOut[i], r1P2P[i], err = s.SignRound1()
		require.NoError(t, err)
	}

	return signerOut, r1P2P
}

func signRound2(t *testing.T, signers map[uint32]*Signer, signerOut map[uint32]*Round1Bcast, r1P2P map[uint32]map[uint32]*Round1P2PSend, playerMin int, useDistributed bool) map[uint32]map[uint32]*P2PSend {
	var (
		p2p = make(map[uint32]map[uint32]*P2PSend)

		r1P2pIn map[uint32]*Round1P2PSend
	)

	for i := uint32(1); i <= uint32(playerMin); i++ {
		var cosigners []uint32

		for j := uint32(1); j <= uint32(playerMin); j++ {
			if i != j {
				cosigners = append(cosigners, j)
			}
		}

		err := signers[i].setCosigners(cosigners)
		require.NoError(t, err)

		if useDistributed {
			r1P2pIn = make(map[uint32]*Round1P2PSend, playerMin)

			for j := uint32(1); j <= uint32(playerMin); j++ {
				if i != j {
					r1P2pIn[j] = r1P2P[j][i]
				}
			}
		}

		params := map[uint32]*Round1Bcast{}

		for j := uint32(1); j <= uint32(playerMin); j++ {
			if i != j {
				params[j] = signerOut[j]
			}
		}

		p2p[i], err = signers[i].SignRound2(params, r1P2pIn)
		require.NoError(t, err)
	}

	return p2p
}

func signRound3(t *testing.T, signers map[uint32]*Signer, p2p map[uint32]map[uint32]*P2PSend, playerMin int) map[uint32]*Round3Bcast {
	var err error

	round3Bcast := make(map[uint32]*Round3Bcast, playerMin)

	for i := uint32(1); i <= uint32(playerMin); i++ {
		signP2P := map[uint32]*P2PSend{}

		for j := uint32(1); j <= uint32(playerMin); j++ {
			if i != j {
				signP2P[j] = p2p[j][i]
			}
		}

		round3Bcast[i], err = signers[i].SignRound3(signP2P)
		require.NoError(t, err)
	}

	return round3Bcast
}

func signRound4(t *testing.T, signers map[uint32]*Signer, round3Bcast map[uint32]*Round3Bcast, playerMin int) map[uint32]*Round4Bcast {
	var err error

	round4Bcast := make(map[uint32]*Round4Bcast, playerMin)

	for i := uint32(1); i <= uint32(playerMin); i++ {
		signP2P := map[uint32]*Round3Bcast{}

		for j := uint32(1); j <= uint32(playerMin); j++ {
			if i != j {
				signP2P[j] = round3Bcast[j]
			}
		}

		round4Bcast[i], err = signers[i].SignRound4(signP2P)
		require.NoError(t, err)
	}

	return round4Bcast
}

// todo
func signRound5(t *testing.T, curve elliptic.Curve, pk *curves.EcPoint, signers map[uint32]*Signer, round4Bcast map[uint32]*Round4Bcast, playerMin int) (map[uint32]*Round5Bcast, map[uint32]map[uint32]*Round5P2PSend) {
	var err error

	round5Bcast := make(map[uint32]*Round5Bcast, playerMin)
	r5P2p := make(map[uint32]map[uint32]*Round5P2PSend, playerMin)

	round5Bcast[1], r5P2p[1], err = signers[1].SignRound5(map[uint32]*Round4Bcast{2: round4Bcast[2], 3: round4Bcast[3]})
	require.NoError(t, err)

	round5Bcast[2], r5P2p[2], err = signers[2].SignRound5(map[uint32]*Round4Bcast{1: round4Bcast[1], 3: round4Bcast[3]})
	require.NoError(t, err)

	round5Bcast[3], r5P2p[3], err = signers[3].SignRound5(map[uint32]*Round4Bcast{1: round4Bcast[1], 2: round4Bcast[2]})
	require.NoError(t, err)

	Rbark, err := signers[1].state.Rbark.Add(signers[2].state.Rbark)
	require.NoError(t, err)

	Rbark, err = Rbark.Add(signers[3].state.Rbark)
	require.NoError(t, err)

	Rbark.Y, err = core.Neg(Rbark.Y, curve.Params().P)
	require.NoError(t, err)

	Rbark, err = Rbark.Add(pk)
	require.NoError(t, err)

	if !Rbark.IsIdentity() {
		t.Errorf("%v != %v", Rbark.X, pk.X)
		t.FailNow()
	}

	return round5Bcast, r5P2p
}

// todo
func signRound6(t *testing.T, msg []byte, signers map[uint32]*Signer, round5Bcast map[uint32]*Round5Bcast, r5P2P map[uint32]map[uint32]*Round5P2PSend, playerMin int, useDistributed bool) {
	var err error

	var r6P2pin map[uint32]*Round5P2PSend

	if useDistributed {
		// Check failure cases, first with nil input
		// then with missing participant data
		_, err = signers[1].SignRound6Full(msg, map[uint32]*Round5Bcast{2: round5Bcast[2], 3: round5Bcast[3]}, r6P2pin)
		require.Error(t, err)

		r6P2pin = make(map[uint32]*Round5P2PSend, playerMin)
		_, err = signers[1].SignRound6Full(msg, map[uint32]*Round5Bcast{2: round5Bcast[2], 3: round5Bcast[3]}, r6P2pin)

		require.Error(t, err)

		r6P2pin[2] = r5P2P[2][1]
		_, err = signers[1].SignRound6Full(msg, map[uint32]*Round5Bcast{2: round5Bcast[2], 3: round5Bcast[3]}, r6P2pin)
		require.Error(t, err)

		r6P2pin[3] = r5P2P[3][1]
	}

	round6FullBcast := make([]*Round6FullBcast, playerMin)
	round6FullBcast[0], err = signers[1].SignRound6Full(msg, map[uint32]*Round5Bcast{2: round5Bcast[2], 3: round5Bcast[3]}, r6P2pin)
	require.Nil(t, err)

	if useDistributed {
		r6P2pin = make(map[uint32]*Round5P2PSend, playerMin)
		r6P2pin[1] = r5P2P[1][2]
		r6P2pin[3] = r5P2P[3][2]
	}

	round6FullBcast[1], err = signers[2].SignRound6Full(msg, map[uint32]*Round5Bcast{1: round5Bcast[1], 3: round5Bcast[3]}, r6P2pin)
	require.Nil(t, err)

	if useDistributed {
		r6P2pin = make(map[uint32]*Round5P2PSend, playerMin)
		r6P2pin[1] = r5P2P[1][3]
		r6P2pin[2] = r5P2P[2][3]
	}

	round6FullBcast[2], err = signers[3].SignRound6Full(msg, map[uint32]*Round5Bcast{1: round5Bcast[1], 2: round5Bcast[2]}, r6P2pin)
	require.Nil(t, err)
	require.NoError(t, err)

	sigs := make([]*curves.EcdsaSignature, 3)

	sigs[0], err = signers[1].SignOutput(map[uint32]*Round6FullBcast{
		2: round6FullBcast[1],
		3: round6FullBcast[2],
	})
	require.NoError(t, err)

	sigs[1], err = signers[2].SignOutput(map[uint32]*Round6FullBcast{
		1: round6FullBcast[0],
		3: round6FullBcast[2],
	})
	require.NoError(t, err)

	sigs[2], err = signers[3].SignOutput(map[uint32]*Round6FullBcast{
		1: round6FullBcast[0],
		2: round6FullBcast[1],
	})
	require.NoError(t, err)
}
