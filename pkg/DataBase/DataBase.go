package DataBase

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
)

// 定义数据库连接信息
const (
	DBUsername = "root"
	DBPassword = "123456"
	DBHost     = "localhost"
	DBPort     = 3306
	DBName     = "users"
)

// ConnectToDB 连接到数据库
func ConnectToDB() (*sql.DB, error) {
	// 构建数据库连接字符串
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", DBUsername, DBPassword, DBHost, DBPort, DBName)

	// 连接数据库
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return db, nil
}

// CreateTableIfNotExists 如果表不存在就创建一个
func CreateTableIfNotExists(db *sql.DB) error {
	query := `
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nickName VARCHAR(8) NOT NULL,
        userName VARCHAR(10) NOT NULL,
        passWord VARCHAR(32) NOT NULL
    )
    `
	_, err := db.Exec(query)
	if err != nil {
		return err
	}
	return nil
}

// Login 登录
func Login(username, password string, db *sql.DB) int {
	query0 := `SELECT count(*) FROM users WHERE userName = ?`
	row0 := db.QueryRow(query0, username)
	var count int
	row0.Scan(&count)
	// 如果有相同的用户名就返回error
	if count == 0 {
		return 1 //fmt.Errorf("Do not have this UserName\n")
	}
	query := `SELECT * FROM users WHERE  userName = ? AND passWord = ?`
	row := db.QueryRow(query, username, password)
	var (
		id       int
		NickName string
		UserName string
		PassWord string
	)
	Err := row.Scan(&id, &NickName, &UserName, &PassWord)
	if Err != nil {
		if Err == sql.ErrNoRows {
			// 查询结果为空，用户名和密码不匹配
			return 2 //fmt.Errorf("Password error\n")
		}
	}
	return 0
}

// Register 注册
func Register(nickname, username, password string, db *sql.DB, token string) error {
	err := Check(username, db)
	// 用户名重复
	if err != nil {
		return err
	}
	// 没有就开始注册
	// 执行插入语句
	query := `INSERT INTO users (nickName, userName, passWord) VALUES (?, ?, ?)`
	_, err = db.Exec(query, nickname, username, password)
	if err != nil {
		return err
	}
	return nil
}

// Check 检查用户名是否重复
func Check(username string, db *sql.DB) error {
	// 检查表是否存在，如果不存在则创建表
	if err := CreateTableIfNotExists(db); err != nil {
		return err
	}
	// 先检测是否有相同的用户名
	query := `SELECT COUNT(*) FROM users WHERE userName = ?`
	row := db.QueryRow(query, username)
	var count int
	row.Scan(&count)
	// 如果有相同的用户名就返回error
	if count != 0 {
		return fmt.Errorf("Exist UserName\n")
	}
	return nil
}

// GetNickName 获得昵称
func GetNickName(Username string) (string, error) {
	db, err := ConnectToDB()
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	defer db.Close()
	query := `SELECT * FROM users WHERE  userName = ?`
	row := db.QueryRow(query, Username)
	var (
		id       int
		NickName string
		UserName string
		PassWord string
	)
	Err := row.Scan(&id, &NickName, &UserName, &PassWord)
	if Err != nil {
		fmt.Println(Err)
		return "", Err
	}
	return NickName, nil
}

func ChangePassword(Username, oldPassword, newPassword string, db *sql.DB) (int, error) {
	/*	query0 := `SELECT * FROM users WHERE  userName = ? AND passWord = ?`
		row0 := db.QueryRow(query, Username, Password)
		var (
			id       int
			NickName string
			UserName string
			PassWord string
		)
		Err := row0.Scan(&id, &NickName, &UserName, &PassWord)
		if Err != nil {
			fmt.Println(Err)
			return "", Err
		}
		// 存在这个用户名 密码是否相同
		if Password != PassWord {
			return "Error Pwd", nil
		}*/
	query := `UPDATE users SET passWord = ? WHERE userName = ? AND passWord = ?`
	result, err := db.Exec(query, newPassword, Username, oldPassword)
	if err != nil {
		// 发生了一个错误，进行错误处理
		// 可以根据具体错误类型进行相应的处理逻辑
		if err == sql.ErrNoRows {
			// 用户名不存在错误
			// 执行相应的操作
			fmt.Println("用户名不存在")
			return 1, err
		}
	} else {
		// 更新密码成功
		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			// 密码错误
			fmt.Println("密码错误")
			return 2, nil
			// 执行相应的操作
		} else {
			// 密码更新成功
			// 执行相应的操作
			fmt.Println("密码更新成功")
		}
	}
	return 0, nil
}
