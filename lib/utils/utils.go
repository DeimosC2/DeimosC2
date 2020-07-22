package utils

import (
	"bytes"
	"compress/gzip"
	"io"
	"io/ioutil"

	"github.com/DeimosC2/DeimosC2/lib/crypto"
	"github.com/DeimosC2/DeimosC2/lib/logging"
)

//PrepData encrypts and compresses data to be sent for DNS listeners
func PrepData(agentKey string, data []byte, aesKey []byte) []byte {
	toEnc := append([]byte(agentKey), data...)
	encMsg := crypto.Encrypt(toEnc, aesKey)
	var b bytes.Buffer
	err := GzipWrite(encMsg, &b)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	return b.Bytes()
}

//HandleIncomingData unzips and then decrypts data
func HandleIncomingData(data []byte, aesKey []byte) []byte {
	dcData := bytes.Buffer{}
	if err := GunzipWrite(data, &dcData); err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	decMsg := crypto.Decrypt(dcData.Bytes(), aesKey)
	return decMsg
}

// GzipWrite data to a Writer
func GzipWrite(data []byte, w io.Writer) error {
	// Write gzipped data to the client
	gw, err := gzip.NewWriterLevel(w, gzip.BestCompression)
	defer gw.Close()
	gw.Write(data)

	return err
}

// GunzipWrite data to a Writer
func GunzipWrite(data []byte, w io.Writer) error {
	// Write gzipped data to the client
	gr, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer gr.Close()

	data, err = ioutil.ReadAll(gr)
	if err != nil {
		return err
	}
	w.Write(data)

	return nil
}
