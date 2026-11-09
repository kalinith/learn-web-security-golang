package uploads

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

const signedDownloadTTL = 5 * time.Minute

func CreateSignedDownloadPath(signingKey [32]byte, fileID int64, now time.Time) string {
	expires := now.Unix() + int64(signedDownloadTTL.Seconds())
	signature := signDownload(signingKey, fileID, expires)
	return fmt.Sprintf("/files/%d/signed-download?expires=%d&signature=%s", fileID, expires, signature)
}

func VerifySignedDownload(signingKey [32]byte, fileID int64, expiresValue, signature string, now time.Time) bool {
	if expiresValue == "" || strings.Trim(expiresValue, "0123456789") != "" || len(signature) != 64 {
		return false
	}
	expires, err := strconv.ParseInt(expiresValue, 10, 64)
	if err != nil {
		return false
	}
	expectedSignature := signDownload(signingKey, fileID, expires)
	signatureBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	expectedSignatureBytes, err := hex.DecodeString(expectedSignature)
	if err != nil {
		return false
	}
	if subtle.ConstantTimeCompare(signatureBytes, expectedSignatureBytes) != 1 {
		return false
	}
	return expires > now.Unix()
}

func signDownload(signingKey [32]byte, fileID, expires int64) string {
	mac := hmac.New(sha256.New, signingKey[:])
	mac.Write([]byte(fmt.Sprintf("GET\n/files/%d/signed-download\n%d", fileID, expires)))
	return hex.EncodeToString(mac.Sum(nil))
}
