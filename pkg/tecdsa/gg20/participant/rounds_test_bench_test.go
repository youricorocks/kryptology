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
	fullRoundTestUseDistributed(t, curve, msg, verify, 5, 10, false)
	fullRoundTestUseDistributed(t, curve, msg, verify, 5, 10, true)
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

	sk := signers[1].share.Value

	for i := uint32(2); i <= uint32(playerMin); i++ {
		sk = sk.Add(signers[i].share.Value)
	}

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

func signRound5(t *testing.T, curve elliptic.Curve, pk *curves.EcPoint, signers map[uint32]*Signer, round4Bcast map[uint32]*Round4Bcast, playerMin int) (map[uint32]*Round5Bcast, map[uint32]map[uint32]*Round5P2PSend) {
	var (
		err error

		round5Bcast = make(map[uint32]*Round5Bcast, playerMin)
		r5P2p       = make(map[uint32]map[uint32]*Round5P2PSend, playerMin)
	)

	for i := uint32(1); i <= uint32(playerMin); i++ {
		witnesses := map[uint32]*Round4Bcast{}

		for j := uint32(1); j <= uint32(playerMin); j++ {
			if i != j {
				witnesses[j] = round4Bcast[j]
			}
		}

		round5Bcast[i], r5P2p[i], err = signers[i].SignRound5(witnesses)
		require.NoError(t, err)
	}

	rBark := signers[1].state.Rbark

	for i := uint32(2); i <= uint32(playerMin); i++ {
		rBark, err = rBark.Add(signers[i].state.Rbark)
		require.NoError(t, err)
	}

	rBark.Y, err = core.Neg(rBark.Y, curve.Params().P)
	require.NoError(t, err)

	rBark, err = rBark.Add(pk)
	require.NoError(t, err)

	if !rBark.IsIdentity() {
		t.Errorf("%v != %v", rBark.X, pk.X)
		t.FailNow()
	}

	return round5Bcast, r5P2p
}

func signRound6(t *testing.T, msg []byte, signers map[uint32]*Signer, round5Bcast map[uint32]*Round5Bcast, r5P2P map[uint32]map[uint32]*Round5P2PSend, playerMin int, useDistributed bool) {
	var err error

	var r6P2pin map[uint32]*Round5P2PSend

	if useDistributed {
		r6P2pin = make(map[uint32]*Round5P2PSend, playerMin)

		// check failure cases, first with nil input then with missing participant data
		for k := uint32(0); k < uint32(playerMin); k++ {
			in := map[uint32]*Round5Bcast{}

			for j := uint32(1); j <= uint32(playerMin); j++ {
				if j != 1 {
					in[j] = round5Bcast[j]
				}
			}

			_, err = signers[1].SignRound6Full(msg, in, r6P2pin)
			require.Error(t, err)

			if k > 0 {
				r6P2pin[k+1] = r5P2P[k+1][1]
			}
		}
	}

	round6FullBcast := make([]*Round6FullBcast, playerMin)

	for i := uint32(1); i <= uint32(playerMin); i++ {
		in := map[uint32]*Round5Bcast{}

		for j := uint32(1); j <= uint32(playerMin); j++ {
			if i != j {
				in[j] = round5Bcast[j]
			}
		}

		if useDistributed && i > 1 {
			r6P2pin = make(map[uint32]*Round5P2PSend, playerMin)

			for j := uint32(1); j <= uint32(playerMin); j++ {
				if i != j {
					r6P2pin[j] = r5P2P[j][i]
				}
			}
		}

		round6FullBcast[i-1], err = signers[i].SignRound6Full(msg, in, r6P2pin)
		require.NoError(t, err)
	}

	sigs := make([]*curves.EcdsaSignature, playerMin)

	for i := uint32(1); i <= uint32(playerMin); i++ {
		in := map[uint32]*Round6FullBcast{}

		for j := uint32(1); j <= uint32(playerMin); j++ {
			if i != j {
				in[j] = round6FullBcast[j-1]
			}
		}

		sigs[i-1], err = signers[i].SignOutput(in)
		require.NoError(t, err)
	}
}
