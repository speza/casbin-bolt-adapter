package boltadapter

import (
	"encoding/csv"
	"encoding/json"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	bolt "github.com/coreos/bbolt"
	"strings"
)

func loadPolicy(rule CasbinRule, model model.Model) {
	lineText := rule.PType

	if rule.V0 != "" {
		lineText += ", " + rule.V0
	}
	if rule.V1 != "" {
		lineText += ", " + rule.V1
	}
	if rule.V2 != "" {
		lineText += ", " + rule.V2
	}
	if rule.V3 != "" {
		lineText += ", " + rule.V3
	}
	if rule.V4 != "" {
		lineText += ", " + rule.V4
	}
	if rule.V5 != "" {
		lineText += ", " + rule.V5
	}

	persist.LoadPolicyLine(lineText, model)
}

func loadCsvPolicyLine(line string, model model.Model) error {
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}

	reader := csv.NewReader(strings.NewReader(line))
	reader.TrimLeadingSpace = true
	tokens, err := reader.Read()
	if err != nil {
		return err
	}

	key := tokens[0]
	sec := key[:1]
	model[sec][key].Policy = append(model[sec][key].Policy, tokens[1:])
	return nil
}

func convertRule(ptype string, line []string) CasbinRule {
	rule := CasbinRule{PType: ptype}

	keySlice := []string{ptype}

	l := len(line)
	if l > 0 {
		rule.V0 = line[0]
		keySlice = append(keySlice, line[0])
	}
	if l > 1 {
		rule.V1 = line[1]
		keySlice = append(keySlice, line[1])
	}
	if l > 2 {
		rule.V2 = line[2]
		keySlice = append(keySlice, line[2])
	}
	if l > 3 {
		rule.V3 = line[3]
		keySlice = append(keySlice, line[3])
	}
	if l > 4 {
		rule.V4 = line[4]
		keySlice = append(keySlice, line[4])
	}
	if l > 5 {
		rule.V5 = line[5]
		keySlice = append(keySlice, line[5])
	}

	rule.Key = strings.Join(keySlice, "::")

	return rule
}

func (a *adapter) putLine(bucket *bolt.Bucket, ptype string, line []string) error {
	pLine := convertRule(ptype, line)

	bts, err := json.Marshal(pLine)
	if err != nil {
		return err
	}

	return bucket.Put([]byte(pLine.Key), bts)
}
