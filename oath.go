/*
 * yubo@yubo.org
 * 2015-10
 */

package oath

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"time"
)

func Validate(secret, otp string, window int) (v bool, err error) {
	v, _, err = Validate_otp(secret, otp, true, 6,
		time.Now().Unix(), 30, int64(window))
	return
}

func Oath(secret string, window int) (string, error) {
	if ret, err := Oath_otp(secret, true, 6,
		time.Now().Unix(), 30, 1); err != nil {
		return "", err
	} else {
		return ret[0], nil
	}
}

func Oaths(secret string, window int) (ret []string, err error) {
	return Oath_otp(secret, true, 6,
		time.Now().Unix(), 30, int64(window))
}

func Oath_otp(secret string, b32 bool,
	digits int, nowSec, step, window int64) (ret []string, err error) {
	var (
		passcode string
	)

	key, err := get_key(b32, secret)
	if err != nil {
		return ret, err
	}

	counter := nowSec / step
	for i := int64(0); i < window; i++ {
		if passcode, err = gen_otp(counter, key, digits); err != nil {
			err = fmt.Errorf("Failed to generate passcode: %s", err)
			return
		} else {
			ret = append(ret, passcode)
			counter++
		}
	}
	return
}

func Validate_otp(secret, otp string, b32 bool,
	digits int, nowSec, step, window int64) (bool, int64, error) {

	counter := nowSec/step - window/2

	if len(otp) != digits {
		return false, nowSec, nil
	}

	key, err := get_key(b32, secret)
	if err != nil {
		return false, nowSec, err
	}

	for i := int64(0); i < window; i++ {
		code, _ := gen_otp(counter, key, digits)
		if code == otp {
			return true, counter, nil
		}
		counter++
	}
	return false, counter, nil
}

func get_key(b32 bool, secret string) ([]byte, error) {
	if b32 {
		return base32.StdEncoding.DecodeString(secret)
	} else {
		return hex.DecodeString(secret)
	}
}

func gen_otp(counter int64, key []byte, digits int) (p string, err error) {
	hash := hmac.New(sha1.New, key)

	if err = binary.Write(hash, binary.BigEndian, counter); err != nil {
		return
	}

	h := hash.Sum(nil)
	offset := h[19] & 0x0f
	trunc := binary.BigEndian.Uint32(h[offset : offset+4])
	trunc &= 0x7fffffff
	code := trunc % uint32(math.Pow(10, float64(digits)))

	return fmt.Sprintf("%0"+strconv.Itoa(digits)+"d", code), nil
}
