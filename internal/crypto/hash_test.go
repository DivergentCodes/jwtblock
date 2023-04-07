package crypto

import (
	"testing"
)

func Test_Sha256FromString_Success(t *testing.T) {
	plainText := "foobar"
	hashText := "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2"

	result := Sha256FromString(plainText)
	if result != hashText {
		t.Errorf("Hash mismatch: text=%s, expected=%s, actual=%s", plainText, hashText, result)
	}
}

func Test_IsValidSha256_ValidHash_Success(t *testing.T) {
	hashText := "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2"
	err := IsValidSha256(hashText)
	if err != nil {
		t.Errorf("Expected valid Sha256: hashText=%s", err)
	}

}

func Test_IsValidSha256_InvalidHash_Error(t *testing.T) {
	hashText := "!3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2"
	err := IsValidSha256(hashText)
	if err == nil {
		t.Errorf("Expected invalid Sha256 with symbol: hashText=%s", err)
	}

	hashText = "3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2"
	err = IsValidSha256(hashText)
	if err == nil {
		t.Errorf("Expected invalid Sha256 with fewer characters: hashText=%s", err)
	}

	hashText = "xxc3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2"
	err = IsValidSha256(hashText)
	if err == nil {
		t.Errorf("Expected invalid Sha256 with more characters: hashText=%s", err)
	}
}
