package netflow

import (
	"bufio"
	"io"
	"os"
	"strings"
)

var (
	systemUsers map[string]string
)

func init() {
	loadSystemUsersInfo()
}

func loadSystemUsersInfo() {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return
	}
	defer f.Close()

	systemUsers = make(map[string]string)
	bf := bufio.NewReader(f)
	for {
		line, err := bf.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
		}

		items := strings.Split(line, ":")
		if len(items) != 2 {
			return
		}

		systemUsers[items[2]] = items[0]
	}
}

func getUserByUID(uid string) string {
	return systemUsers[uid]
}
