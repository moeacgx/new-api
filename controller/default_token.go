package controller

import (
	"errors"
	"fmt"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
)

func createDefaultTokenForUser(user *model.User) error {
	if !constant.GenerateDefaultToken || user == nil || user.Id == 0 {
		return nil
	}

	tokenUser := *user
	if strings.TrimSpace(tokenUser.Username) == "" || strings.TrimSpace(tokenUser.Group) == "" {
		freshUser, err := model.GetUserById(user.Id, true)
		if err != nil {
			common.SysLog(fmt.Sprintf("failed to load user %d before default token creation: %s", user.Id, err.Error()))
			return errors.New("获取用户信息失败")
		}
		tokenUser = *freshUser
	}

	key, err := common.GenerateKey()
	if err != nil {
		common.SysLog("failed to generate default token key: " + err.Error())
		return errors.New("生成默认令牌失败")
	}

	token := model.Token{
		UserId:             tokenUser.Id,
		Name:               tokenUser.Username + "的初始令牌",
		Key:                key,
		CreatedTime:        common.GetTimestamp(),
		AccessedTime:       common.GetTimestamp(),
		ExpiredTime:        -1,
		RemainQuota:        500000,
		UnlimitedQuota:     true,
		ModelLimitsEnabled: false,
	}
	token.Group = resolveTokenGroupForCreate("", tokenUser.Group)
	if err := token.Insert(); err != nil {
		common.SysLog(fmt.Sprintf("failed to create default token for user %d: %s", user.Id, err.Error()))
		return errors.New("创建默认令牌失败")
	}

	return nil
}
