package attack

import (
	"errors"
	"fmt"
	"strings"

	"github.com/bliey/zipkit/internal/zipservice"
)

// 来源对比的结论。
const (
	// VerdictSame 表示两边都是高置信度且来源相同。
	VerdictSame = "same"
	// VerdictDiffer 表示两边都是高置信度但来源不同。
	VerdictDiffer = "differ"
	// VerdictUnsure 表示置信度不够，不做判断。
	VerdictUnsure = "unsure"
	// VerdictUnknown 表示至少一边完全认不出来，不做判断。
	VerdictUnknown = "unknown"
)

// CreatorPair 是明文攻击面板里「来源对比」的完整结果。
//
// 这是**辅助信息**，不参与也不替代 Precheck 的压缩方式 / CRC 比对，
// 更不会阻止用户开始攻击。
type CreatorPair struct {
	Encrypted zipservice.Creator `json:"encrypted"`
	Plain     zipservice.Creator `json:"plain"`
	// Verdict 取 same / differ / unsure / unknown。
	Verdict string `json:"verdict"`
	// Message 是直接显示给用户的一句话结论。
	Message string `json:"message"`
}

// DetectCreators 分别识别加密 ZIP 与明文 ZIP 的来源，并给出一致性结论。
//
// 判定规则（只有两边都是 high 才下结论）：
//
//   - 都是 high 且软件名相同 → same；
//   - 都是 high 但软件名不同 → differ；
//   - 任一边是 unknown     → unknown（认不出来就别比）；
//   - 其余（medium / low）  → unsure（置信度不够，仅供参考）。
//
// 之所以这么严：指纹表里有多家软件共用同一组字节的行，凭结构分不出 360压缩
// 与 7-Zip、Bandizip 与 WinRAR。宁可说「仅供参考」，也不给用户一个假的
// 「一致」让他白跑一次攻击。
func DetectCreators(encryptedZip, plainZip string) (CreatorPair, error) {
	if strings.TrimSpace(encryptedZip) == "" {
		return CreatorPair{}, errors.New("attack: 没有指定加密压缩包")
	}
	if strings.TrimSpace(plainZip) == "" {
		return CreatorPair{}, errors.New("attack: 没有指定明文 ZIP")
	}

	enc, err := zipservice.DetectCreator(encryptedZip)
	if err != nil {
		return CreatorPair{}, fmt.Errorf("attack: 识别加密包的来源失败：%w", err)
	}
	plain, err := zipservice.DetectCreator(plainZip)
	if err != nil {
		return CreatorPair{}, fmt.Errorf("attack: 识别明文包的来源失败：%w", err)
	}

	pair := CreatorPair{Encrypted: enc, Plain: plain}

	switch {
	// 「来源未知」按名字判断，而不是只看 confidence：退化指纹行会给出
	// Name=Unknown + Confidence=low，这种情况同样没有可比的厂商名。
	case enc.Name == zipservice.CreatorUnknown || plain.Name == zipservice.CreatorUnknown ||
		enc.Confidence == zipservice.ConfidenceUnknown || plain.Confidence == zipservice.ConfidenceUnknown:
		pair.Verdict = VerdictUnknown
		pair.Message = "来源未知，不做一致性判断；仍可直接尝试攻击。"
	case enc.Confidence != zipservice.ConfidenceHigh || plain.Confidence != zipservice.ConfidenceHigh:
		pair.Verdict = VerdictUnsure
		pair.Message = "来源识别置信度较低，仅供参考；请以 Precheck 的压缩方式与 CRC 比对为准。"
	case enc.Name == plain.Name:
		pair.Verdict = VerdictSame
		pair.Message = fmt.Sprintf("两者来源一致（%s），建议直接尝试攻击。", enc.Name)
	default:
		pair.Verdict = VerdictDiffer
		pair.Message = fmt.Sprintf(
			"两者来源不一致（加密=%s，明文=%s），明文攻击成功率可能较低；"+
				"建议用创建加密文件的同一软件重新压缩明文。", enc.Name, plain.Name)
	}
	return pair, nil
}
