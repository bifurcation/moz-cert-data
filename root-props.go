package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

// These types have just enough to parse what we need
type RootStore map[string]RootEntry

type RootEntry struct {
	Certificate string    `json:"CKA_VALUE"`
	Trust       RootTrust `json:"trust"`
}

type RootTrust struct {
	ServerAuth string `json:"CKA_TRUST_SERVER_AUTH"`
}

const (
	trusted  = "CKT_NSS_TRUSTED_DELEGATOR"
	algECDSA = "ECDSA"
	algRSA   = "RSA"
)

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	rootStoreData, err := ioutil.ReadFile("certdata.json")
	panicOnError(err)

	var rootStore RootStore
	err = json.Unmarshal(rootStoreData, &rootStore)
	panicOnError(err)

	// Basic stats
	processed := 0
	skippedNonServerAuth := 0
	skippedBadBase64 := 0
	skippedBadDER := 0
	good := 0

	// X.509 stats
	algDist := map[string]int{}
	ecCurveDist := map[string]int{}
	rsaKeySizeDist := map[int]int{}

	for label, entry := range rootStore {
		processed += 1

		if entry.Trust.ServerAuth != trusted {
			skippedNonServerAuth += 1
			continue
		}

		certDER, err := base64.StdEncoding.DecodeString(entry.Certificate)
		if err != nil {
			skippedBadBase64 += 1
			fmt.Fprintf(os.Stderr, "Error decoding base64 for label [%s]", label)
			continue
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			skippedBadDER += 1
			fmt.Fprintf(os.Stderr, "Error  for label [%s]", label)
			continue
		}

		good += 1

		switch cert.PublicKeyAlgorithm {
		case x509.ECDSA:
			algDist[algECDSA] += 1

			pubKey := cert.PublicKey.(*ecdsa.PublicKey)
			if pubKey != nil {
				curveName := pubKey.Params().Name
				ecCurveDist[curveName] += 1
			} else {
				ecCurveDist["invalid"] += 1
			}

		case x509.RSA:
			algDist[algRSA] += 1

			pubKey := cert.PublicKey.(*rsa.PublicKey)
			if pubKey != nil {
				keySize := pubKey.N.BitLen()
				rsaKeySizeDist[keySize] += 1
			} else {
				rsaKeySizeDist[0] += 1
			}
		}
	}

	fmt.Printf("%d entries in certdata.txt\n", processed)
	fmt.Printf("%d ... trusted for serverAuth\n", good)
	fmt.Println()

	fmt.Println("Algorithm distribution:")
	for alg, count := range algDist {
		fmt.Printf("  %-7s%d\n", alg, count)
	}
	fmt.Println()

	fmt.Println("ECDSA curve distribution:")
	for curve, count := range ecCurveDist {
		fmt.Printf("  %-7s%d\n", curve, count)
	}
	fmt.Println()

	fmt.Println("RSA key size distribution:")
	for size, count := range rsaKeySizeDist {
		fmt.Printf("  %-7d%d\n", size, count)
	}
	fmt.Println()
}
