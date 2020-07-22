package mfa

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"strings"

	"github.com/AdvancedThreatAnalytics/DeimosC2/c2/webserver/googauth"
	"github.com/AdvancedThreatAnalytics/DeimosC2/lib/logging"
	"github.com/aaronarduino/goqrsvg"
	svg "github.com/ajstarks/svgo"
	"github.com/boombuler/barcode/qr"
)

//GenerateNewSecretAndImage for users to use for setting up their MFA
func GenerateNewSecretAndImage(user string, issuer string) (string, string, error) {
	//Generate secret
	secret := make([]byte, 10)
	_, err := rand.Read(secret)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	secretBase32 := base32.StdEncoding.EncodeToString(secret)

	//Setup the link for OTP according to the following specifications https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	authLink := "otpauth://totp/" + user + "?secret=" + secretBase32 + "&issuer=" + issuer

	//Setup the code variable to be a QR with the authLink
	code, _ := qr.Encode(authLink, qr.M, qr.Auto)

	//Generate the QR to SVG
	buf := bytes.NewBufferString("")
	svgQR := svg.New(buf)
	qs := goqrsvg.NewQrSVG(code, 5)
	qs.StartQrSVG(svgQR)
	qs.WriteQrSVG(svgQR)
	svgQR.End()

	//SVG Encode bytes to b64
	svgEncode := base64.StdEncoding.EncodeToString(buf.Bytes())

	//Return the secret, the QR code, and no error
	return secretBase32, svgEncode, nil
}

//IsTokenValid checks to ensure the token is valid
func IsTokenValid(tokenSecret string, token string) bool {
	//Calls to OTP to ensure the calls are only made once
	otpConfig := &googauth.OTPConfig{
		Secret:      strings.TrimSpace(tokenSecret),
		WindowSize:  3,
		HotpCounter: 0,
		UTC:         true,
	}

	trimmedToken := strings.TrimSpace(token)

	//Validate token
	ok, err := otpConfig.Authenticate(trimmedToken)

	if err != nil || !ok {
		return false
	}
	return true
}
