package main

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	tunnel_checks "github.com/khulnasoft/tunnel-checks"
	"gopkg.in/yaml.v3"
)

const (
	commandPath = "commands/kubernetes"
)

func main() {
	ids, err := GetCommandIDRange()
	if err != nil {
		panic(err)
	}
	fmt.Println("The following Command ID id free.")
	for i := 0; i < len(ids); i++ {
		if !ids[i] {
			println(fmt.Sprintf("%s %s-%04d", "K8s Command:", "CMD", i+1))
			return
		}
	}
}
func GetCommandIDRange() ([]bool, error) {
	commandsIds := make([]bool, 9999)
	entries, err := tunnel_checks.EmbeddedK8sCommandsFileSystem.ReadDir(commandPath)
	if err != nil {
		panic(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fContent, err := tunnel_checks.EmbeddedK8sCommandsFileSystem.ReadFile(filepath.Join(commandPath, entry.Name()))
		if err != nil {
			return nil, err
		}
		var fileCommand any
		err = yaml.Unmarshal(fContent, &fileCommand)
		if err != nil {
			panic(err)
		}

		if commandArr, ok := fileCommand.([]interface{}); ok {
			if commandMap, ok := commandArr[0].(map[any]any); ok {
				if id, ok := commandMap["id"]; ok {
					idStr := id.(string)
					idWithoutPrefix := strings.TrimPrefix(idStr, "CMD-")
					idNum, err := strconv.Atoi(idWithoutPrefix)
					if err != nil {
						return nil, err
					}
					if idNum > 0 && idNum <= 9999 {
						commandsIds[idNum-1] = true
					}
				}
			}
		}
	}
	return commandsIds, nil
}
