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
)

var (
	obj object
)

// Init - инициализация
func Init(p Param) {
	obj.param = p

	if obj.param.WriteTime == 0 {
		obj.param.WriteTime = 60
	}

	obj.readFile()
}

// Get - получаем сессию
func Get(key string) (s Data) {
	obj.RLock()
	s = obj.data[key]
	obj.RUnlock()
	return
}

// Exist - проверка есть ли такой ключ
func Exist(key string) (ok bool) {
	obj.RLock()
	_, ok = obj.data[key]
	obj.RUnlock()
	return
}

// Set - Вставка новой сессии
func Set(key string, id int) {
	obj.Lock()
	obj.data[key] = Data{ID: id, Time: time.Now()}
	obj.Unlock()

	// Пишем изменения в файл
	obj.writeFile()
}

// Delete - удаяем сессии
func Delete(uid int) {
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
	obj.writeFile()
}

// Create - Создаем сессию
func Create(id int) (cookie string, err error) {

	k := strconv.FormatInt(int64(id), 32) + strconv.FormatInt(time.Now().UnixNano(), 32) +
		strconv.FormatInt(rand.Int63(), 32)

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
		for k, v := range obj.data {
			log.Println(k, v)
		}
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
