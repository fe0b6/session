package session

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"math/rand"
	"strconv"
	"time"

	"github.com/fe0b6/ramstore"
	"github.com/fe0b6/tools"

	"github.com/fe0b6/cdb"
)

const prefix = "session:"

var (
	obj object
)

// Init - инициализация
func Init(p Param) (exitChan chan bool) {
	obj.param = p

	if obj.param.WriteTime == 0 {
		obj.param.WriteTime = 60
	}

	exitChan = make(chan bool)

	go waitExit(exitChan)

	if p.Type == "cdb" {
	} else {
		obj.readFile()
	}
	return
}

// Ждем сигнал о выходе
func waitExit(exitChan chan bool) {
	_ = <-exitChan

	if obj.param.Type == "cdb" {
	} else {
		obj.writeFile(true)
	}

	exitChan <- true
}

// Get - получаем сессию
func Get(key string) (s Data) {
	if obj.param.Type == "cdb" {
		cdb.Cdb.GetObj(prefix+key, &s)
		return
	}

	obj.RLock()
	s = obj.data[key]
	obj.RUnlock()
	return
}

// Exist - проверка есть ли такой ключ
func Exist(key string) (ok bool) {
	if obj.param.Type == "cdb" {
		_, err := cdb.Cdb.Get(prefix + key)
		if err == nil {
			ok = true
		}
		return
	}

	obj.RLock()
	_, ok = obj.data[key]
	obj.RUnlock()
	return
}

// Set - Вставка новой сессии
func Set(key string, id int64) {
	if obj.param.Type == "cdb" {
		cdb.Cdb.SetObjEx(prefix+key, Data{ID: id, Time: time.Now()}, int(obj.param.InactiveTime))
		return
	}

	obj.Lock()
	obj.data[key] = Data{ID: id, Time: time.Now()}
	obj.Unlock()

	// Пишем изменения в файл
	obj.writeFile(false)
}

// Delete - удаяем сессии
func Delete(uid int64) {
	if obj.param.Type == "cdb" {
		keys := []string{}
		cdb.Cdb.Search(prefix, func(k string, o ramstore.Obj) {
			var s Data
			tools.FromGob(&s, o.Data)
			if s.ID == uid {
				keys = append(keys, k)
			}
		})

		for _, k := range keys {
			cdb.Cdb.Del(k)
		}
		return
	}

	obj.Lock()
	// Ищем сессии
	for k, v := range obj.data {
		// Удаляем сессии
		if v.ID == uid {
			delete(obj.data, k)
		}
	}
	obj.Unlock()

	// Пишем изменения в файл
	obj.writeFile(false)
}

// Create - Создаем сессию
func Create(id int64) (cookie string, err error) {

	k := strconv.FormatInt(int64(id), 32) + strconv.FormatInt(time.Now().UnixNano(), 32) +
		strconv.FormatInt(rand.Int63(), 32)
	m := md5.New()
	m.Write([]byte(k))
	k = hex.EncodeToString(m.Sum(nil))

	// Проверяем что такой сессии еще нет
	if Exist(k) {
		log.Println("[error]", "session key exist", k)
		return Create(id)
	}

	// Сохраняем сессию
	Set(k, id)

	// Создаем подпись для сессии
	sign := Sign(k)

	// Собираем сессию
	cookie = k + sign

	return
}

// Check - Проверяем сессию
func Check(key string) (d Data, err error) {
	// Ищем сессию
	d = Get(key[0:32])
	if d.ID == 0 {
		err = errors.New("Сессия не найдена")
		return
	}

	// Проверяем контрольную сумму
	if Sign(key[0:32]) != key[32:64] {
		err = errors.New("Неправильная сумма")
		log.Println("[error]", err, key)
		return
	}

	// Обновляем время сессии
	Set(key[0:32], d.ID)
	return
}

// Sign - Получаем подпись сессии
func Sign(k string) (sign string) {
	b := []byte(k)

	for i := 0; i < 10; i++ {
		// Время
		hasher := sha256.New()
		hasher.Write(b)
		hasher.Write([]byte(obj.param.Secret))
		b = hasher.Sum(nil)
	}

	h := hmac.New(md5.New, []byte(obj.param.Secret))
	h.Write(b)

	return hex.EncodeToString(h.Sum(nil))
}
