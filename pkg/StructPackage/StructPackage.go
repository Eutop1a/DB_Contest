package StructPackage

import (
	"github.com/dgrijalva/jwt-go"
	//"github.com/golang-jwt/jwt/v5"
	"time"
)

// TokenData token和过期时间
type TokenData struct {
	EndTime time.Time `json:"EndTime"`
	Token   string    `json:"Token"`
}

// RegMsg 定义账号和密码结构体
type RegMsg struct {
	Nickname string `json:"nickname"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type LogMsg struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type CheckMsg struct {
	Username string `join:"username"`
}

type MyClaims struct {
	UserName string `json:"UserName"`
	jwt.StandardClaims
}
