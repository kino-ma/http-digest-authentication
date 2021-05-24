package main

import (
	"crypto/md5"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"strings"

	"github.com/k0kubun/pp"
)

var (
	// 使用済みのncを保存する
	usedNc = make(map[string]bool)
	// サーバが送信するnonce
	nonce = os.Getenv("DIGEST_NONCE")
)

func getKeyValuePair(content string) map[string]string {
	// "Digest hoge=a, fuga=b"
	// -> ["hoge=a", "fuga=b"]
	re := regexp.MustCompile(`[a-z]+="?[^" ,]+"?`)
	kvpairs := re.FindAllString(content, -1)

	res := make(map[string]string)

	for _, pair := range kvpairs {
		// "key=value"
		// -> {key: value}
		arr := strings.Split(pair, "=")
		key := arr[0]

		value := strings.Replace(arr[1], `"`, "", -1)

		res[key] = value
	}

	return res
}

func verifyDigestRequest(user, passwd, realm string, r *http.Request) bool {
	// パラメータを取り出す
	// username="hoge", ...
	authorization := r.Header.Get("Authorization")
	params := getKeyValuePair(authorization)

	pp.Printf("request params: %v\n", params)

	// A1を作る
	// A1 = username ":" realm ":" passwordd
	a1 := fmt.Sprintf("%s:%s:%s", params["username"], realm, passwd)

	// A2を作る
	// A2 = method ":" uri
	println("uri: ", r.RequestURI)
	a2 := fmt.Sprintf("%s:%s", r.Method, r.RequestURI)

	// MD5(A1), MD5(A2)
	hashedA1, hashedA2 := md5.Sum([]byte(a1)), md5.Sum([]byte(a2))

	// 検証用のresponseを計算する
	// response = MD5( MD5(A1) ":" nonce ":" nc ":" cnonce ":" qop ":" MD5(A2) )
	calculatedResponseRaw := fmt.Sprintf("%x:%s:%s:%s:%s:%x", hashedA1, params["nonce"], params["nc"], params["cnonce"], params["qop"], hashedA2)
	calculatedResponseHashed := md5.Sum([]byte(calculatedResponseRaw))
	calculatedResponse := fmt.Sprintf("%x", calculatedResponseHashed[:])

	responseFromClient := params["response"]

	// それぞれが正当なパラメータか
	_, ncExists := usedNc[params["nc"]]
	ncValid := !ncExists // まだ使われていなければ正当
	nonceValid := params["nonce"] == string(nonce)
	responseValid := responseFromClient == calculatedResponse

	if !(ncValid && nonceValid && responseValid) {
		pp.Printf("invalid parameters!\n")
	}

	return ncValid && nonceValid && responseValid
}

func handlerDigest(w http.ResponseWriter, r *http.Request) {
	if _, ok := r.Header["Authorization"]; !ok {
		// 認証情報を要求する
		realm := os.Getenv("DIGEST_REALM")

		headerContent := fmt.Sprintf(`Digest realm="%s", nonce="%s", algorithm=MD5, qop="auth"`, realm, nonce)
		w.Header().Add("WWW-Authenticate", headerContent)

		w.WriteHeader(http.StatusUnauthorized)
	} else {
		// 認証情報を検証する

		// ユーザ情報
		user := os.Getenv("DIGEST_USER")
		passwd := os.Getenv("DIGEST_PASSWD")
		realm := os.Getenv("DIGEST_REALM")

		// 検証
		valid := verifyDigestRequest(user, passwd, realm, r)

		if valid {
			// pass
			fmt.Fprintf(w, "<html><body>super secret page</body></html>\n")
		} else {
			// fail
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "<html><body>invalid parameters!</body></html>\n")
		}
	}
}

func main() {
	var httpServer http.Server

	http.HandleFunc("/", handlerDigest)

	log.Println("start http listening :18888")
	httpServer.Addr = ":18888"
	log.Println(httpServer.ListenAndServe())
}
