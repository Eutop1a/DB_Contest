package Security

import (
	"crypto/md5"
	"fmt"
	"github.com/dgrijalva/jwt-go"

	"modulename/pkg/StructPackage"
	"time"
)

var JwtSecret string = "tmLV8XB_GkavfmEdY1qX05wjxLyUvTB7YIFQlhM35W0Bfsf_xJLKmbHveikK1jml9v4v4Xij7vyIou2PI0Zejxt5fHLkc4ySIj390mniQk1iOLljVJYCPRR9i__yYkYmb5JoG-8nf8uCfVYAHaAbkziN3bGoU7ykhxMVgfZbdmSKOjM59Pjw2e16EidcyF0S8VKMECiPuEmV1gN8W5NPzQF6g4go3A0ROaKo3X5CzEd1aU1_e8TY2ZTLEqeMM_PHKAF6IJ3eucK8QvTQn8D8ZQmccX0QIcrHrnZHfG0lP1oE39XvnXJ290nMh4hHG985yjxh4SmgOPeyzuCb3Q2o4w=="

/*// 签名密钥
const signKey = "HelloWorld"

var letters = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

func randStr(Len int) string {
	randBytes := make([]rune, Len)
	for i := range randBytes {
		randBytes[i] = letters[rand.Intn(len(letters))]
	}
	return string(randBytes)
}*/

// MD5 md5加密函数
func MD5(str string) string {
	data := []byte(str) //切片
	hash := md5.Sum(data)
	md5str := fmt.Sprintf("%x", hash) //将[]byte转成16进制
	return md5str
}

/*
// GenerateToken 生成token
func GenerateToken(Uname string, expirationTime time.Time) (string, error) {
	claim := StructPackage.MyCustomClaims{
		Username: Uname,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "Administrator",                               // 签发者
			Subject:   "Developer",                                   // 签发对象
			Audience:  jwt.ClaimStrings{"Android_APP", "IOS_APP"},    //签发受众
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)), //过期时间
			NotBefore: jwt.NewNumericDate(time.Now()),                //最早使用时间
			IssuedAt:  jwt.NewNumericDate(time.Now()),                //签发时间
			ID:        randStr(10),                                   // wt ID, 类似于盐值
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claim).SignedString([]byte(signKey))
	return token, err
}

func ParseTokenHs256(tokenString string) (*SMyCustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(signKey), nil // 返回签名密钥
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*MyCustomClaims)
	if !ok {
		return nil, errors.New("invalid claim type")
	}

	if !token.Valid {
		return nil, errors.New("claim invalid")
	}

	// 检查Token是否过期
	if claims.ExpiresAt != nil && time.Now().Unix() > *claims.ExpiresAt {
		return nil, errors.New("token has expired")
	}

	return claims, nil
}*/

// GenerateToken 生成token
func GenerateToken(Uname string, expirationTime time.Time) (string, error) {
	claims := &StructPackage.MyClaims{
		UserName: Uname,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(), // 过期时间
			IssuedAt:  time.Now().Unix(),     // 发布时间
			Subject:   "token",               // 主题
			Issuer:    "Administrator",       // 发布者
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(JwtSecret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// ParseToken 解析token
func ParseToken(tokenString string) int {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(JwtSecret), nil
	})

	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorExpired != 0 {
				fmt.Println("Token has expired")
				return 1
			} else {
				fmt.Println("Error parsing token:", err.Error())
				return 2
			}
		} else {
			fmt.Println("Error parsing token:", err.Error())
			return 3
		}
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		username := claims["UserName"].(string) // 修改此处字段名为 "UserName"
		// role := claims["role"].(string)         // 修改此处字段名为 "role"

		fmt.Println("Username:", username)
		// fmt.Println("Role:", role)
	} else {
		fmt.Println("Invalid token")
	}
	return 0
}
