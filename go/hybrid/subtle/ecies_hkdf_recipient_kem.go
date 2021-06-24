// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package subtle

import (
	"fmt"

	"github.com/google/tink/go/subtle"
)

// ECIESHKDFRecipientKem represents a HKDF-based KEM (key encapsulation mechanism)
// for ECIES recipient.
type ECIESHKDFRecipientKem struct {
	recipientPrivateKey *ECPrivateKey
}

// decapsulate uses the KEM to generate a new HKDF-based key.
func (s *ECIESHKDFRecipientKem) decapsulate(kem []byte, hashAlg string, salt []byte, info []byte, keySize uint32, pointFormat string) ([]byte, error) {

	fmt.Println("Received KEM", kem)

	pubPoint, err := PointDecode(s.recipientPrivateKey.PublicKey.Curve, pointFormat, kem)
	if err != nil {
		return nil, err
	}

	fmt.Println("pubPoint.X", pubPoint.X.Bytes())
	fmt.Println("pubPoint.Y", pubPoint.Y.Bytes())

	secret, err := ComputeSharedSecret(pubPoint, s.recipientPrivateKey)
	if err != nil {
		return nil, err
	}

	fmt.Println("SharedSecret", secret)
	i := append(kem, secret...)

	fmt.Println("ComputeHKDF.input", i)

	return subtle.ComputeHKDF(hashAlg, i, salt, info, keySize)
}
