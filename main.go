package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"modulename/pkg/DataBase"
	"modulename/pkg/RpcFunc"
	"modulename/pkg/Security"
	"modulename/pkg/StructPackage"
	"net/http"
	"net/rpc"
	"time"
)

// 处理注册请求
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析请求体中的 JSON 数据
	var data StructPackage.RegMsg
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// 将密码进行md5加密之后再存储到数据库中
	pwd := Security.MD5(data.Password)

	// 连接数据库
	db, err := DataBase.ConnectToDB()
	if err != nil {
		return
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)
	err = DataBase.CreateTableIfNotExists(db)
	if err != nil {
		return
	}

	// 存储到 MySQL 数据库
	if err := DataBase.Register(data.Nickname, data.Username, pwd, db, ""); err != nil {
		log.Printf("该用户名已经存在：%v\n", err)
		http.Error(w, "UserName already exist", http.StatusConflict) // 409
		return
	}
	// 创建token
	// 先设置过期时间
	expirationTime := time.Now().Add(10 * time.Hour)
	token, err := Security.GenerateToken(data.Username, expirationTime)
	if err != nil {
		fmt.Println("Generate token error")
		return
	}

	fmt.Println("token: ", token)
	// 将token和EndTime打包发送给前端
	SendData := StructPackage.TokenData{
		EndTime: expirationTime,
		Token:   token,
	}
	// 将TokenData对象转换为JSON格式
	jsonData, err := json.Marshal(SendData)
	if err != nil {
		log.Println("JSON encoding error:", err)
		return
	}
	// 返回响应
	w.WriteHeader(http.StatusOK) // 200
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(jsonData)
	if err != nil {
		log.Println("Error sending JSON response:", err)
	}
}

// 处理登录请求
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析请求体中的 JSON 数据
	var data StructPackage.LogMsg
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// 将密码进行md5加密之后再存储到数据库中
	pwd := Security.MD5(data.Password)

	// 连接数据库
	db, err := DataBase.ConnectToDB()
	if err != nil {
		return
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)
	// 登录
	if err := DataBase.Login(data.Username, pwd, db); err != 0 {
		switch err {
		case 1:
			w.WriteHeader(http.StatusNotFound)
		case 2:
			w.WriteHeader(http.StatusUnauthorized)
		}
		return
	}

	// 创建token
	// 过期时间
	expirationTime := time.Now().Add(10 * time.Hour)
	token, err := Security.GenerateToken(data.Username, expirationTime)
	if err != nil {
		fmt.Println("Generate token error")
		return
	}
	fmt.Printf("token: %s\n", token)
	// 返回响应
	// 将token和EndTime打包发送给前端
	SendData := StructPackage.TokenData{
		EndTime: expirationTime,
		Token:   token,
	}

	// 将TokenData对象转换为JSON格式
	jsonData, err := json.Marshal(SendData)
	if err != nil {
		log.Println("JSON encoding error:", err)
		return
	}
	// 返回响应
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(jsonData)
	if err != nil {
		log.Println("Error sending JSON response:", err)
	}
}

// 检查是否有相同的用户名
func checkHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析请求体中的 JSON 数据
	var data StructPackage.CheckMsg
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	fmt.Printf("账号：%s\n", data.Username)
	// 连接数据库
	db, err := DataBase.ConnectToDB()
	if err != nil {
		return
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)
	err = DataBase.CreateTableIfNotExists(db)
	if err != nil {
		return
	}
	// 检查是否有重复
	if err := DataBase.Check(data.Username, db); err != nil {
		response := "1"
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(response))

		return
	}

	// 返回响应
	response := "0"
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(response))

}

// 返回nickname
func getNickNameHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	// 解析请求体中的 JSON 数据
	var data StructPackage.CheckMsg
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	fmt.Println(data.Username)
	NickName, err := DataBase.GetNickName(data.Username)
	if err != nil {
		fmt.Println("Get NickName error")
		return
	}
	response := NickName
	w.Header().Set("Content-Type", "text/plain")
	_, err = w.Write([]byte(response))
	if err != nil {
		fmt.Println(err)
	}

}

// Check Token
func checkToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	// 解析请求体中的 JSON 数据
	var data StructPackage.TokenData
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	fmt.Println(data.Token)
	ErrorType := Security.ParseToken(data.Token)
	switch ErrorType {
	case 0:
		// token解析成功
		w.WriteHeader(http.StatusOK) //200
		fmt.Println("token解析成功")
		break
	case 1:
		// token过期
		w.WriteHeader(http.StatusUnauthorized) //401
		fmt.Println("token过期")
		break
	case 2:
		// token解析失败
		w.WriteHeader(http.StatusBadRequest) //400
		fmt.Println("token解析失败")
		break
	}
	return
}

// 修改密码
func changePwd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	// 解析请求体中的 JSON 数据
	var data StructPackage.LogMsg
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	// 连接数据库
	db, err := DataBase.ConnectToDB()
	if err != nil {
		return
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)
	// 将所有的信息传入进行处理
	newPwd := Security.MD5(data.Password)
	flag, Err := DataBase.ChangePassword(data.Username, data.Password, newPwd, db)
	if flag == 1 && Err != nil {
		// 用户名不存在
		w.WriteHeader(http.StatusNotFound)
	}
	if flag == 2 {
		// 密码错误
		w.WriteHeader(http.StatusUnauthorized)
	}
	// 更新成功
	w.WriteHeader(http.StatusOK)
}

// 忘记密码
func forgotPwd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	// 解析请求体中的 JSON 数据
	var data StructPackage.TokenData
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
}

// 注销
func unsubscribe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	// 解析请求体中的 JSON 数据
	var data StructPackage.TokenData
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
}

func main() {
	// 异步启动
	// 注册rpc函数
	rpc.Register(new(RpcFunc.Token))

	// 启动RPC服务器
	go func() {
		rpc.HandleHTTP()
		log.Printf("Serving RPC server on port %d", 8081)
		if err := http.ListenAndServe(":8081", nil); err != nil {
			log.Fatal("Error serving RPC server: ", err)
		}
	}()

	// 启动HTTP服务器
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/check", checkHandler)
	http.HandleFunc("/get", getNickNameHandler)
	http.HandleFunc("/open", checkToken)
	http.HandleFunc("/changePwd", changePwd)
	http.HandleFunc("/forgotPwd", forgotPwd)
	http.HandleFunc("/unsubscribe", unsubscribe)
	http.Handle("/", http.FileServer(http.Dir("static")))
	log.Println("HTTP服务器启动，监听端口 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))

}
