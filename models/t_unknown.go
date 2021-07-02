package models

import ()

// SetTargetUnknownString
func (rc *RecordConfig) SetTargetUnknownString(raw string) error {
	rc.SetTarget(raw)
	return nil
}
