package session

import (
	"bytes"
	"encoding/gob"
	"io/ioutil"
	"log"
	"os"
	"time"
)

// Читайм файл сессий
func (obj *object) readFile() {

	// Пробуем прочитать базу
	dFile, err := os.Open(obj.param.Path)
	if err == nil {
		defer dFile.Close()

		dec := gob.NewDecoder(dFile)
		err = dec.Decode(&obj.data)
		if err != nil {
			log.Fatalln("[fatal]", "decode:", err)
			return
		}
	} else {
		obj.data = make(map[string]Data)
	}

	// Запускаем таймер проверки устаревания сессий
	go func(obj *object) {
		for {
			obj.checkExpires()
			time.Sleep(60 * time.Minute)
		}
	}(obj)
}

// Пишем сессии в файл
func (obj *object) writeFile() {
	// Проверяем как давно записывали, и если недавно то не обновляем ничего
	obj.Fsync.RLock()
	if obj.writeTime.Add(obj.param.WriteTime * time.Minute).After(time.Now()) {
		obj.Fsync.RUnlock()
		return
	}
	obj.Fsync.RUnlock()

	// Конвертируем объект сессий в gob
	var data bytes.Buffer
	enc := gob.NewEncoder(&data)

	obj.RLock()
	err := enc.Encode(obj.data)
	obj.RUnlock()

	if err != nil {
		log.Println("[error]", err)
		return
	}

	// Пишем данные в файл
	obj.Fsync.Lock()
	err = ioutil.WriteFile(obj.param.Path, data.Bytes(), 0640)
	obj.writeTime = time.Now()
	obj.Fsync.Unlock()

	if err != nil {
		log.Println("[error]", err)
	}
}

// Удаляем истекшие сессии
func (obj *object) checkExpires() {

	obj.RLock()

	// Чистим старые сессии
	delKeys := []string{}
	now := time.Now().Unix()
	for k, v := range obj.data {
		if now-obj.param.InactiveTime > v.Time.Unix() {
			delKeys = append(delKeys, k)
		}
	}

	obj.RUnlock()

	// Если что-то удалили - пересохраним сессии
	if len(delKeys) > 0 {
		obj.Lock()
		for _, k := range delKeys {
			delete(obj.data, k)
		}
		obj.Unlock()

		// Обновляем файл сессий
		obj.writeFile()
	}
}
