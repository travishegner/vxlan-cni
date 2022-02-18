package lock

import (
	"fmt"
	"os"

	"github.com/alexflint/go-filemutex"
)

//Lock represents a filesystem based mutex on a whole vxlan
//this allows us to effectively serialize any accesses to an individual network's interfaces
type Lock struct {
	Name  string
	mutex *filemutex.FileMutex
}

//NewLock returns a new Lock
func NewLock(name, path, ext string) (*Lock, error) {
	fm, err := filemutex.New(path + string(os.PathSeparator) + "vxlan-" + name + ext)
	if err != nil {
		return nil, fmt.Errorf("failed to create new filemutex: %w", err)
	}

	return &Lock{
		Name:  name,
		mutex: fm,
	}, nil
}

//Lock acquires a lock on the vxlan
func (l *Lock) Lock() {
	l.mutex.Lock()
}

//Unlock removes the lock on the vxlan
func (l *Lock) Unlock() {
	l.mutex.Unlock()
}

//Close unlocks and closes the underlying file descriptor
func (l *Lock) Close() {
	l.mutex.Close()
}
