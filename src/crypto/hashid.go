/*
 * This script is a to GO converted version, the original
 * script can be found below:
 *
 * hash-identifier:
 * 		https://github.com/blackploit/hash-identifier/blob/master/hash-id.py
 * 		By Zion3R
 * 		www.Blackploit.com
 * 		Root@Blackploit.com
 */

package crypto

import (
	"strconv"
	"strings"
	"unicode"
)

var AlgoNames = map[string]string{
	"102020":  "ADLER-32",
	"102040":  "CRC-32",
	"102060":  "CRC-32B",
	"101020":  "CRC-16",
	"101040":  "CRC-16-CCITT",
	"104020":  "DES(Unix)",
	"101060":  "FCS-16",
	"103040":  "GHash-32-3",
	"103020":  "GHash-32-5",
	"115060":  "GOST R 34.11-94",
	"109100":  "Haval-160",
	"109200":  "Haval-160(HMAC)",
	"110040":  "Haval-192",
	"110080":  "Haval-192(HMAC)",
	"114040":  "Haval-224",
	"114080":  "Haval-224(HMAC)",
	"115040":  "Haval-256",
	"115140":  "Haval-256(HMAC)",
	"107080":  "Lineage II C4",
	"106025":  "Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))",
	"102080":  "XOR-32",
	"105060":  "MD5(Half)",
	"105040":  "MD5(Middle)",
	"105020":  "MySQL",
	"107040":  "MD5(phpBB3)",
	"107060":  "MD5(Unix)",
	"107020":  "MD5(Wordpress)",
	"108020":  "MD5(APR)",
	"106160":  "Haval-128",
	"106165":  "Haval-128(HMAC)",
	"106060":  "MD2",
	"106120":  "MD2(HMAC)",
	"106040":  "MD4",
	"106100":  "MD4(HMAC)",
	"106020":  "MD5",
	"106080":  "MD5(HMAC)",
	"106140":  "MD5(HMAC(Wordpress))",
	"106029":  "NTLM",
	"106027":  "RAdmin v2.x",
	"106180":  "RipeMD-128",
	"106185":  "RipeMD-128(HMAC)",
	"106200":  "SNEFRU-128",
	"106205":  "SNEFRU-128(HMAC)",
	"106220":  "Tiger-128",
	"106225":  "Tiger-128(HMAC)",
	"106240":  "md5($pass.$salt)",
	"106260":  "md5($salt.'-'.md5($pass))",
	"106280":  "md5($salt.$pass)",
	"106300":  "md5($salt.$pass.$salt)",
	"106320":  "md5($salt.$pass.$username)",
	"106340":  "md5($salt.md5($pass))",
	"106360":  "md5($salt.md5($pass).$salt)",
	"106380":  "md5($salt.md5($pass.$salt))",
	"106400":  "md5($salt.md5($salt.$pass))",
	"106420":  "md5($salt.md5(md5($pass).$salt))",
	"106440":  "md5($username.0.$pass)",
	"106460":  "md5($username.LF.$pass)",
	"106480":  "md5($username.md5($pass).$salt)",
	"106500":  "md5(md5($pass))",
	"106520":  "md5(md5($pass).$salt)",
	"106540":  "md5(md5($pass).md5($salt))",
	"106560":  "md5(md5($salt).$pass)",
	"106580":  "md5(md5($salt).md5($pass))",
	"106600":  "md5(md5($username.$pass).$salt)",
	"106620":  "md5(md5(md5($pass)))",
	"106640":  "md5(md5(md5(md5($pass))))",
	"106660":  "md5(md5(md5(md5(md5($pass)))))",
	"106680":  "md5(sha1($pass))",
	"106700":  "md5(sha1(md5($pass)))",
	"106720":  "md5(sha1(md5(sha1($pass))))",
	"106740":  "md5(strtoupper(md5($pass)))",
	"109040":  "MySQL5 - SHA-1(SHA-1($pass))",
	"109060":  "MySQL 160bit - SHA-1(SHA-1($pass))",
	"109180":  "RipeMD-160(HMAC)",
	"109120":  "RipeMD-160",
	"109020":  "SHA-1",
	"109140":  "SHA-1(HMAC)",
	"109220":  "SHA-1(MaNGOS)",
	"109240":  "SHA-1(MaNGOS2)",
	"109080":  "Tiger-160",
	"109160":  "Tiger-160(HMAC)",
	"109260":  "sha1($pass.$salt)",
	"109280":  "sha1($salt.$pass)",
	"109300":  "sha1($salt.md5($pass))",
	"109320":  "sha1($salt.md5($pass).$salt)",
	"109340":  "sha1($salt.sha1($pass))",
	"109360":  "sha1($salt.sha1($salt.sha1($pass)))",
	"109380":  "sha1($username.$pass)",
	"109400":  "sha1($username.$pass.$salt)",
	"1094202": "sha1(md5($pass))",
	"109440":  "sha1(md5($pass).$salt)",
	"109460":  "sha1(md5(sha1($pass)))",
	"109480":  "sha1(sha1($pass))",
	"109500":  "sha1(sha1($pass).$salt)",
	"109520":  "sha1(sha1($pass).substr($pass,0,3))",
	"109540":  "sha1(sha1($salt.$pass))",
	"109560":  "sha1(sha1(sha1($pass)))",
	"109580":  "sha1(strtolower($username).$pass)",
	"110020":  "Tiger-192",
	"110060":  "Tiger-192(HMAC)",
	"112020":  "md5($pass.$salt) - Joomla",
	"113020":  "SHA-1(Django)",
	"114020":  "SHA-224",
	"114060":  "SHA-224(HMAC)",
	"115080":  "RipeMD-256",
	"115160":  "RipeMD-256(HMAC)",
	"115100":  "SNEFRU-256",
	"115180":  "SNEFRU-256(HMAC)",
	"115200":  "SHA-256(md5($pass))",
	"115220":  "SHA-256(sha1($pass))",
	"115020":  "SHA-256",
	"115120":  "SHA-256(HMAC)",
	"116020":  "md5($pass.$salt) - Joomla",
	"116040":  "SAM - (LM_hash:NT_hash)",
	"117020":  "SHA-256(Django)",
	"118020":  "RipeMD-320",
	"118040":  "RipeMD-320(HMAC)",
	"119020":  "SHA-384",
	"119040":  "SHA-384(HMAC)",
	"120020":  "SHA-256",
	"121020":  "SHA-384(Django)",
	"122020":  "SHA-512",
	"122060":  "SHA-512(HMAC)",
	"122040":  "Whirlpool",
	"122080":  "Whirlpool(HMAC)",
}

func isDigit(s string) bool {
	if _, err := strconv.Atoi(s); err == nil {
		return true
	}

	return false
}

const alpha = "abcdefghijklmnopqrstuvwxyz"

func isAlpha(s string) bool {
	for _, char := range s {
		if !strings.Contains(alpha, strings.ToLower(string(char))) {
			return false
		}
	}
	return true
}

const alphanum = "abcdefghijklmnopqrstuvwxyz0123456789"

func isAlphaNum(s string) bool {
	for _, char := range s {
		if !strings.Contains(alphanum, strings.ToLower(string(char))) {
			return false
		}
	}
	return true
}

func isLower(s string) bool {
	for _, r := range s {
		if !unicode.IsLower(r) && unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

func IdentifyHash(hash string) []string {
	var res []string
	var hs string

	// ADLER32
	hs = "0607cb42"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "102020")
	}

	// CRC16
	hs = "4607"
	if len(hash) == len(hs) && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "101020")
	}

	// CRC16CCITT
	hs = "3d08"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "101040")
	}

	// CRC32
	hs = "b33fd057"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "102040")
	}

	// CRC32B
	hs = "b764a0d9"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "102060")
	}

	// DESUnix
	hs = "ZiY8YtDKXJwYQ"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false {
		res = append(res, "104020")
	}

	// DomainCachedCredentials
	hs = "f42005ec1afe77967cbc83dce1b4d714"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106025")
	}

	// FCS16
	hs = "0e5b"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "101060")
	}

	// GHash323
	hs = "80000000"
	if len(hash) == len(hs) && isDigit(hash) == true && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "103040")
	}

	// GHash325
	hs = "85318985"
	if len(hash) == len(hs) && isDigit(hash) == true && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "103020")
	}

	// GOSTR341194
	hs = "ab709d384cce5fda0793becd3da0cb6a926c86a8f3460efb471adddee1c63793"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "115060")
	}

	// Haval128
	hs = "d6e3ec49aa0f138a619f27609022df10"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106160")
	}

	// Haval128HMAC
	hs = "3ce8b0ffd75bc240fc7d967729cd6637"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106165")
	}

	// Haval160
	hs = "a106e921284dd69dad06192a4411ec32fce83dbb"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109100")
	}

	// Haval160HMAC
	hs = "29206f83edc1d6c3f680ff11276ec20642881243"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109200")
	}

	// Haval192
	hs = "cd3a90a3bebd3fa6b6797eba5dab8441f16a7dfa96c6e641"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "110040")
	}

	// Haval192HMAC
	hs = "39b4d8ecf70534e2fd86bb04a877d01dbf9387e640366029"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "110080")
	}

	// Haval224
	hs = "f65d3c0ef6c56f4c74ea884815414c24dbf0195635b550f47eac651a"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "114040")
	}

	// Haval224HMAC
	hs = "f10de2518a9f7aed5cf09b455112114d18487f0c894e349c3c76a681"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "114080")
	}

	// Haval256
	hs = "7169ecae19a5cd729f6e9574228b8b3c91699175324e6222dec569d4281d4a4a"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "115040")
	}

	// Haval256HMAC
	hs = "6aa856a2cfd349fb4ee781749d2d92a1ba2d38866e337a4a1db907654d4d4d7a"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "115140")
	}

	// LineageIIC4
	hs = "0x49a57f66bd3d5ba6abda5579c264a0e4"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true && strings.HasPrefix(hash, "0x") {
		res = append(res, "107080")
	}

	// MD2
	hs = "08bbef4754d98806c373f2cd7d9a43c4"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106060")
	}

	// MD2HMAC
	hs = "4b61b72ead2b0eb0fa3b8a56556a6dca"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106120")
	}

	// MD4
	hs = "a2acde400e61410e79dacbdfc3413151"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106040")
	}

	// MD4HMAC
	hs = "6be20b66f2211fe937294c1c95d1cd4f"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106100")
	}

	// MD5
	hs = "ae11fd697ec92c7c98de3fac23aba525"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106020")
	}

	// MD5APR
	hs = "$apr1$qAUKoKlG$3LuCncByN76eLxZAh/Ldr1"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && strings.HasPrefix(hash, "$apr") {
		res = append(res, "108020")
	}

	// MD5HMAC
	hs = "d57e43d2c7e397bf788f66541d6fdef9"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106080")
	}

	// MD5HMACWordpress
	hs = "3f47886719268dfa83468630948228f6"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106140")
	}

	// MD5phpBB3
	hs = "$H$9kyOtE8CDqMJ44yfn9PFz2E.L2oVzL1"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == false && strings.HasPrefix(hash, "$H$") {
		res = append(res, "107040")
	}

	// MD5Unix
	hs = "$1$cTuJH0Ju$1J8rI.mJReeMvpKUZbSlY/"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == false && strings.HasPrefix(hash, "$1$") {
		res = append(res, "107060")
	}

	// MD5Wordpress
	hs = "$P$BiTOhOj3ukMgCci2juN0HRbCdDRqeh."
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == false && strings.HasPrefix(hash, "$P$") {
		res = append(res, "107020")
	}

	// MD5Half
	hs = "ae11fd697ec92c7c"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "105060")
	}

	// MD5Middle
	hs = "7ec92c7c98de3fac"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "105040")
	}

	// MD5passsaltjoomla1
	hs = "35d1c0d69a2df62be2df13b087343dc9:BeKMviAfcXeTPTlX"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == false && hash[32:33] == ":" {
		res = append(res, "112020")
	}

	// MD5passsaltjoomla2
	hs = "fb33e01e4f8787dc8beb93dac4107209:fxJUXVjYRafVauT77Cze8XwFrWaeAYB2"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == false && hash[32:33] == ":" {
		res = append(res, "116020")
	}

	// MySQL
	hs = "63cea4673fd25f46"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "105020")
	}

	// MySQL5
	hs = "9bb2fb57063821c762cc009f7584ddae9da431ff"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109040")
	}

	// MySQL160bit
	hs = "*2470c0c06dee42fd1618bb99005adca2ec9d1e19"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == false && strings.HasPrefix(hash, "*") {
		res = append(res, "109060")
	}

	// NTLM
	hs = "cc348bace876ea440a28ddaeb9fd3550"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106029")
	}

	// RAdminv2x
	hs = "baea31c728cbf0cd548476aa687add4b"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106027")
	}

	// RipeMD128
	hs = "4985351cd74aff0abc5a75a0c8a54115"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106180")
	}

	// RipeMD128HMAC
	hs = "ae1995b931cf4cbcf1ac6fbf1a83d1d3"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106185")
	}

	// RipeMD160
	hs = "dc65552812c66997ea7320ddfb51f5625d74721b"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109120")
	}

	// RipeMD160HMAC
	hs = "ca28af47653b4f21e96c1235984cb50229331359"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109180")
	}

	// RipeMD256
	hs = "5fcbe06df20ce8ee16e92542e591bdea706fbdc2442aecbf42c223f4461a12af"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "115080")
	}

	// RipeMD256HMAC
	hs = "43227322be1b8d743e004c628e0042184f1288f27c13155412f08beeee0e54bf"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "115160")
	}

	// RipeMD320
	hs = "b4f7c8993a389eac4f421b9b3b2bfb3a241d05949324a8dab1286069a18de69aaf5ecc3c2009d8ef"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "118020")
	}

	// RipeMD320HMAC
	hs = "244516688f8ad7dd625836c0d0bfc3a888854f7c0161f01de81351f61e98807dcd55b39ffe5d7a78"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "118040")
	}

	// SAM
	hs = "4318B176C3D8E3DEAAD3B435B51404EE:B7C899154197E8A2A33121D76A240AB5"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == false && isLower(hash) == false && hash[32:33] == ":" {
		res = append(res, "116040")
	}

	// SHA1
	hs = "4a1d4dbc1e193ec3ab2e9213876ceb8f4db72333"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109020")
	}

	// SHA1Django
	hs = "sha1$Zion3R$299c3d65a0dcab1fc38421783d64d0ecf4113448"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == false && strings.HasPrefix(hash, "sha1$") {
		res = append(res, "113020")
	}

	// SHA1HMAC
	hs = "6f5daac3fee96ba1382a09b1ba326ca73dccf9e7"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109140")
	}

	// SHA1MaNGOS
	hs = "a2c0cdb6d1ebd1b9f85c6e25e0f8732e88f02f96"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109220")
	}

	// SHA1MaNGOS2
	hs = "644a29679136e09d0bd99dfd9e8c5be84108b5fd"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109240")
	}

	// SHA224
	hs = "e301f414993d5ec2bd1d780688d37fe41512f8b57f6923d054ef8e59"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "114020")
	}

	// SHA224HMAC
	hs = "c15ff86a859892b5e95cdfd50af17d05268824a6c9caaa54e4bf1514"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "114060")
	}

	// SHA256
	hs = "2c740d20dab7f14ec30510a11f8fd78b82bc3a711abe8a993acdb323e78e6d5e"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "115020")
	}

	// SHA256s
	hs = "$6$g4TpUQzk$OmsZBJFwvy6MwZckPvVYfDnwsgktm2CckOlNJGy9HNwHSuHFvywGIuwkJ6Bjn3kKbB6zoyEjIYNMpHWBNxJ6g."
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == false && strings.HasPrefix(hash, "$6$") {
		res = append(res, "120020")
	}

	// SHA256Django
	hs = "sha256$Zion3R$9e1a08aa28a22dfff722fad7517bae68a55444bb5e2f909d340767cec9acf2c3"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == false && strings.HasPrefix(hash, "sha256") {
		res = append(res, "117020")
	}

	// SHA256HMAC
	hs = "d3dd251b7668b8b6c12e639c681e88f2c9b81105ef41caccb25fcde7673a1132"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "115120")
	}

	// SHA256md5pass
	hs = "b419557099cfa18a86d1d693e2b3b3e979e7a5aba361d9c4ec585a1a70c7bde4"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "115200")
	}

	// SHA256sha1pass
	hs = "afbed6e0c79338dbfe0000efe6b8e74e3b7121fe73c383ae22f5b505cb39c886"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "115220")
	}

	// SHA384
	hs = "3b21c44f8d830fa55ee9328a7713c6aad548fe6d7a4a438723a0da67c48c485220081a2fbc3e8c17fd9bd65f8d4b4e6b"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "119020")
	}

	// SHA384Django
	hs = "sha384$Zion3R$88cfd5bc332a4af9f09aa33a1593f24eddc01de00b84395765193c3887f4deac46dc723ac14ddeb4d3a9b958816b7bba"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == false && strings.HasPrefix(hash, "sha384") {
		res = append(res, "121020")
	}

	// SHA384HMAC
	hs = "bef0dd791e814d28b4115eb6924a10beb53da47d463171fe8e63f68207521a4171219bb91d0580bca37b0f96fddeeb8b"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "119040")
	}

	// SHA512
	hs = "ea8e6f0935b34e2e6573b89c0856c81b831ef2cadfdee9f44eb9aa0955155ba5e8dd97f85c73f030666846773c91404fb0e12fb38936c56f8cf38a33ac89a24e"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "122020")
	}

	// SHA512HMAC
	hs = "dd0ada8693250b31d9f44f3ec2d4a106003a6ce67eaa92e384b356d1b4ef6d66a818d47c1f3a2c6e8a9a9b9bdbd28d485e06161ccd0f528c8bbb5541c3fef36f"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "122060")
	}

	// SNEFRU128
	hs = "4fb58702b617ac4f7ca87ec77b93da8a"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106200")
	}

	// SNEFRU128HMAC
	hs = "59b2b9dcc7a9a7d089cecf1b83520350"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106205")
	}

	// SNEFRU256
	hs = "3a654de48e8d6b669258b2d33fe6fb179356083eed6ff67e27c5ebfa4d9732bb"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "115100")
	}

	// SNEFRU256HMAC
	hs = "4e9418436e301a488f675c9508a2d518d8f8f99e966136f2dd7e308b194d74f9"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "115180")
	}

	// Tiger128
	hs = "c086184486ec6388ff81ec9f23528727"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106220")
	}

	// Tiger128HMAC
	hs = "c87032009e7c4b2ea27eb6f99723454b"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106225")
	}

	// Tiger160
	hs = "c086184486ec6388ff81ec9f235287270429b225"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109080")
	}

	// Tiger160HMAC
	hs = "6603161719da5e56e1866e4f61f79496334e6a10"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109160")
	}

	// Tiger192
	hs = "c086184486ec6388ff81ec9f235287270429b2253b248a70"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "110020")
	}

	// Tiger192HMAC
	hs = "8e914bb64353d4d29ab680e693272d0bd38023afa3943a41"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "110060")
	}

	// Whirlpool
	hs = "76df96157e632410998ad7f823d82930f79a96578acc8ac5ce1bfc34346cf64b4610aefa8a549da3f0c1da36dad314927cebf8ca6f3fcd0649d363c5a370dddb"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "122040")
	}

	// WhirlpoolHMAC
	hs = "77996016cf6111e97d6ad31484bab1bf7de7b7ee64aebbc243e650a75a2f9256cef104e504d3cf29405888fca5a231fcac85d36cd614b1d52fce850b53ddf7f9"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "122080")
	}

	// XOR32
	hs = "0000003f"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "102080")
	}

	// md5passsalt
	hs = "5634cc3b922578434d6e9342ff5913f7"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106240")
	}

	// md5saltmd5pass
	hs = "245c5763b95ba42d4b02d44bbcd916f1"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106260")
	}

	// md5saltpass
	hs = "22cc5ce1a1ef747cd3fa06106c148dfa"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106280")
	}

	// md5saltpasssalt
	hs = "469e9cdcaff745460595a7a386c4db0c"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106300")
	}

	// md5saltpassusername
	hs = "9ae20f88189f6e3a62711608ddb6f5fd"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106320")
	}

	// md5saltmd5saltpass
	hs = "d8f3b3f004d387086aae24326b575b23"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106400")
	}

	// md5saltmd5md5passsalt
	hs = "81f181454e23319779b03d74d062b1a2"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106420")
	}

	// md5username0pass
	hs = "e44a60f8f2106492ae16581c91edb3ba"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106440")
	}

	// md5usernameLFpass
	hs = "654741780db415732eaee12b1b909119"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106460")
	}

	// md5usernamemd5passsalt
	hs = "954ac5505fd1843bbb97d1b2cda0b98f"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106480")
	}

	// md5md5pass
	hs = "a96103d267d024583d5565436e52dfb3"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106500")
	}

	// md5md5passsalt
	hs = "5848c73c2482d3c2c7b6af134ed8dd89"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106520")
	}

	// md5md5passmd5salt
	hs = "8dc71ef37197b2edba02d48c30217b32"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106540")
	}

	// md5md5saltpass
	hs = "9032fabd905e273b9ceb1e124631bd67"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106560")
	}

	// md5md5saltmd5pass
	hs = "8966f37dbb4aca377a71a9d3d09cd1ac"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106580")
	}

	// md5md5usernamepasssalt
	hs = "4319a3befce729b34c3105dbc29d0c40"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106600")
	}

	// md5md5md5pass
	hs = "ea086739755920e732d0f4d8c1b6ad8d"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106620")
	}

	// md5md5md5md5pass
	hs = "02528c1f2ed8ac7d83fe76f3cf1c133f"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106640")
	}

	// md5md5md5md5md5pass
	hs = "4548d2c062933dff53928fd4ae427fc0"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106660")
	}

	// md5sha1pass
	hs = "cb4ebaaedfd536d965c452d9569a6b1e"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106680")
	}

	// md5sha1md5pass
	hs = "099b8a59795e07c334a696a10c0ebce0"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106700")
	}

	// md5sha1md5sha1pass
	hs = "06e4af76833da7cc138d90602ef80070"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106720")
	}

	// md5strtouppermd5pass
	hs = "519de146f1a658ab5e5e2aa9b7d2eec8"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "106740")
	}

	// sha1passsalt
	hs = "f006a1863663c21c541c8d600355abfeeaadb5e4"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109260")
	}

	// sha1saltpass
	hs = "299c3d65a0dcab1fc38421783d64d0ecf4113448"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109280")
	}

	// sha1saltmd5pass
	hs = "860465ede0625deebb4fbbedcb0db9dc65faec30"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109300")
	}

	// sha1saltmd5passsalt
	hs = "6716d047c98c25a9c2cc54ee6134c73e6315a0ff"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109320")
	}

	// sha1saltsha1pass
	hs = "58714327f9407097c64032a2fd5bff3a260cb85f"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109340")
	}

	// sha1saltsha1saltsha1pass
	hs = "cc600a2903130c945aa178396910135cc7f93c63"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109360")
	}

	// sha1usernamepass
	hs = "3de3d8093bf04b8eb5f595bc2da3f37358522c9f"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109380")
	}

	// sha1usernamepasssalt
	hs = "00025111b3c4d0ac1635558ce2393f77e94770c5"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109400")
	}

	// sha1md5pass
	hs = "fa960056c0dea57de94776d3759fb555a15cae87"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "1094202")
	}

	// sha1md5passsalt
	hs = "1dad2b71432d83312e61d25aeb627593295bcc9a"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109440")
	}

	// sha1md5sha1pass
	hs = "8bceaeed74c17571c15cdb9494e992db3c263695"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109460")
	}

	// sha1sha1pass
	hs = "3109b810188fcde0900f9907d2ebcaa10277d10e"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109480")
	}

	// sha1sha1passsalt
	hs = "780d43fa11693b61875321b6b54905ee488d7760"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109500")
	}

	// sha1sha1passsubstrpass03
	hs = "5ed6bc680b59c580db4a38df307bd4621759324e"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109520")
	}

	// sha1sha1saltpass
	hs = "70506bac605485b4143ca114cbd4a3580d76a413"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109540")
	}

	// sha1sha1sha1pass
	hs = "3328ee2a3b4bf41805bd6aab8e894a992fa91549"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109560")
	}

	// sha1strtolowerusernamepass
	hs = "79f575543061e158c2da3799f999eb7c95261f07"
	if len(hash) == len(hs) && isDigit(hash) == false && isAlpha(hash) == false && isAlphaNum(hash) == true {
		res = append(res, "109580")
	}

	return res
}
