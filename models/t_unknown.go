package models

import ()

// SetTargetUnknownString
func (rc *RecordConfig) SetTargetUnknownString(raw string) error {
	rc.TxtStrings = []string{raw}
	rc.SetTarget(raw)
	return nil
}
