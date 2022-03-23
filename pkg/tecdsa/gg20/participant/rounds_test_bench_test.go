package participant

import (
	"crypto/elliptic"
	"flag"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/stretchr/testify/require"
	"html/template"
	"os"
	"testing"
	"time"
)

const Header = `### GG20 bench

| Protocol | Threshold | Count | Curve | MsgLen | Prepossessing rounds time | Online round time | UseDistributed flag |
|----------|-----------|-------|-------|--------|---------------------------|-------------------|---------------------|
`

const Line = `| {{.Protocol}} | {{.Threshold}} | {{.Count}} | {{.Curve}} | {{.MsgLen}} | {{.PrepossessingRoundsTime}} | {{.OnlineRoundTime}} | {{.UseDistributed}} |
`

type TestRun struct {
	Protocol       string
	Threshold      int
	Count          int
	Curve          string
	MsgLen         int
	UseDistributed bool

	PrepossessingStartTime time.Time
	OnlineStartTime        time.Time

	PrepossessingRoundsTime time.Duration
	OnlineRoundTime         time.Duration
}

func (m TestRun) String() string {
	return fmt.Sprintf("%s, curve=%s, threshold=%d, count=%d, msgLen=%d, useDistributed=%v",
		m.Protocol, m.Curve, m.Threshold, m.Count, m.MsgLen, m.UseDistributed)
}

var (
	minCount       = flag.Int("gg20.mincount", 10, "From signers count.")
	maxCount       = flag.Int("gg20.maxcount", 200, "To signers count.")
	countStep      = flag.Int("gg20.countstep", 10, "Signers count step.")
	useDistributed = flag.Bool("gg20.use-distributed", false, "UseDistributed flag.")
	thresholdStart = flag.Float64("gg20.threshold-start", 0.5, "Threshold percent start.")
	thresholdEnd   = flag.Float64("gg20.threshold-end", 1, "Threshold percent end.")
	thresholdStep  = flag.Float64("gg20.threshold-step", 0.5, "Threshold step.")
	curveName      = flag.String("gg20.curve-name", "secp256k1", "Curve name (possible: 'secp256k1', 'secp256r1')")
)

func TestGG20_SignRoundsTime_Secp256k1(t *testing.T) {
	t.Log("Starting bench ...")

	t.Log("Bench configuration:")
	t.Logf("gg20.mincount=%v", minCount)
	t.Logf("gg20.maxcount=%v", maxCount)
	t.Logf("gg20.countstep=%v", countStep)
	t.Logf("gg20.use-distributed=%v", useDistributed)
	t.Logf("gg20.gg20.threshold-start=%v", thresholdStart)
	t.Logf("gg20.threshold-end=%v", thresholdEnd)
	t.Logf("gg20.threshold-step=%v", thresholdStep)
	t.Logf("gg20.curve-name=%v", curveName)

	var curve elliptic.Curve

	msg := []byte{31: 0x01}

	switch *curveName {
	case "secp256k1":
		curve = btcec.S256()
	case "secp256r1":
		curve = elliptic.P256()
	default:
		t.Fatalf("Unknown curve '%s'", curve)
	}

	hash, err := core.Hash(msg, curve)
	require.NoError(t, err)

	outputFile, err := createBenchOutputFile(t)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, outputFile.Close())
	}()

	for count := *minCount; count <= *maxCount; count += *countStep {
		for thresholdPercent := *thresholdStart; thresholdPercent <= *thresholdEnd && thresholdPercent <= 1.0; thresholdPercent += *thresholdStep {
			if thresholdPercent > 1 {
				thresholdPercent = 1
			}

			threshold := int(float64(count) * thresholdPercent)

			m := &TestRun{
				Protocol:       "gg20",
				Threshold:      threshold,
				Count:          count,
				Curve:          *curveName,
				MsgLen:         len(hash.Bytes()),
				UseDistributed: *useDistributed,
			}

			t.Log(m.String())

			t.Run("gg20", func(t *testing.T) {
				fullRoundTest(t, curve, hash.Bytes(), k256Verifier, m)

				m.PrepossessingRoundsTime = m.OnlineStartTime.Sub(m.PrepossessingStartTime)
				m.OnlineRoundTime = time.Now().Sub(m.OnlineStartTime)

				require.NoError(t, appendTestRunToFile(outputFile, m))
			})
		}
	}
}

func fullRoundTest(
	t *testing.T,
	curve elliptic.Curve,
	msg []byte,
	verify curves.EcdsaVerify,
	m *TestRun,
) {
	pk, signers := setupSignersMap(t, curve, m.Threshold, m.Count, false, verify, m.UseDistributed)

	sk := signers[1].share.Value

	for i := uint32(2); i <= uint32(m.Threshold); i++ {
		sk = sk.Add(signers[i].share.Value)
	}

	_, ppk := btcec.PrivKeyFromBytes(curve, sk.Bytes())

	if ppk.X.Cmp(pk.X) != 0 || ppk.Y.Cmp(pk.Y) != 0 {
		t.Errorf("Invalid shares")
		t.FailNow()
	}

	m.PrepossessingStartTime = time.Now()

	// round 1
	signerOut, r1P2P := signRound1(t, signers, m.Count)

	// round 2
	p2p := signRound2(t, signers, signerOut, r1P2P, m.Threshold, m.UseDistributed)

	// round 3
	round3Bcast := signRound3(t, signers, p2p, m.Threshold)

	// round 4
	round4Bcast := signRound4(t, signers, round3Bcast, m.Threshold)

	// round 5
	round5Bcast, r5P2P := signRound5(t, curve, pk, signers, round4Bcast, m.Threshold)

	m.OnlineStartTime = time.Now()

	// round 6
	signRound6(t, msg, signers, round5Bcast, r5P2P, m.Threshold, m.UseDistributed)
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

func createBenchOutputFile(t *testing.T) (*os.File, error) {
	fileName := fmt.Sprintf("./bench_output/%s.md", time.Now().Format(time.RFC3339))

	t.Logf("Bench output file: %s", fileName)

	f, err := os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY|os.O_CREATE, os.ModePerm)
	if err != nil {
		panic(err)
	}

	_, err = f.WriteString(Header)
	if err != nil {
		return nil, err
	}

	return f, nil
}

func appendTestRunToFile(f *os.File, m *TestRun) error {
	t, err := template.New("bench").Parse(Line)
	if err != nil {
		return err
	}

	err = t.Execute(f, *m)
	if err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	return err
}
