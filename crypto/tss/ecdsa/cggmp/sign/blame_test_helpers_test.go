package sign

func (d *Sign) blameUnion() map[string]struct{} {
	d.blamedMu.RLock()
	defer d.blamedMu.RUnlock()
	return d.blameResult.Union()
}
