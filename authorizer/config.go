package authorizer

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"

	"github.com/arrikto/oidc-authservice/authenticator"
	log "github.com/sirupsen/logrus"
	fsnotify "gopkg.in/fsnotify/fsnotify.v1"
	yaml "gopkg.in/yaml.v3"
)

// yaml config based fine-grained group authorization

// AuthzConfig is the authorization schema
type AuthzConfig struct {
	// Rules is a map from host name to HostRule which contain authorization
	// rules that apply to the host
	Rules map[string]HostRule `yaml:"rules"`
}

// HostRule describesauthorization rules for requests that match a given host name
// XXX what to do when there is no rule for a host (the default caes)?
// prob want at least an option to either allow all or require some default groups.
type HostRule struct {
	// groupMatcher map[string]struct{}
	// membership is required for at least 1 group in the list
	Groups []string `yaml:"groups"`
	// XXX could be cool to have an option to require menbership in all groups.
	//     implementation idea - add a `requireAll bool` field that is false by default.
}

type configAuthorizer struct {
	config       *AuthzConfig
	configPath   string
	groupMatcher map[string]map[string]struct{}
	watcher      *fsnotify.Watcher
	lock         sync.RWMutex
}

func NewConfigAuthorizer(configPath string) (Authorizer, error) {
	ca := configAuthorizer{}
	ca.configPath = configPath
	if err := ca.loadConfig(); err != nil {
		return nil, err
	}

	var err error
	ca.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("error creating file watcher: %v", err)
	}

	defer ca.watcher.Close()
	go func() {
		for {
			select {
			case ev, ok := <-ca.watcher.Events:
				if !ok {
					return
				}

				log.Debugf("file watcher event: name=%s op=%s", ev.Name, ev.Op)
				// do nothing on Chmod
				if ev.Op == fsnotify.Chmod {
					continue
				}

				if ev.Op&fsnotify.Remove == fsnotify.Remove {
					// read watcher on remove because fsnotify stops watching
					if err := ca.watcher.Add(ev.Name); err != nil {
						log.Errorf(
							"failed to read watcher for file %q", configPath)
					}
				}

				log.Infof("try to reload config file...")
				if err := ca.loadConfig(); err != nil {
					log.Errorf("failed to reload config: %v", err)
				}
			case err, ok := <-ca.watcher.Errors:
				if !ok {
					return
				}
				log.Infof("watcher error: %v", err)
			}
		}
	}()

	err = ca.watcher.Add(configPath)
	if err != nil {
		log.Fatalf("Error updating file watcher: %v", err)
	}

	return &ca, nil
}

func (ca *configAuthorizer) loadConfig() error {
	authzConfig, err := ca.parseConfig(ca.configPath)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	// build groupMatcher map
	groupMatcher := make(map[string]map[string]struct{})
	for host, rule := range authzConfig.Rules {
		groupMatcher[host] = make(map[string]struct{})
		for _, g := range rule.Groups {
			groupMatcher[host][g] = struct{}{}
		}
	}
	log.Infof("loaded AuthzConfig: %+v", *authzConfig)
	ca.lock.Lock()
	defer ca.lock.Unlock()
	ca.groupMatcher = groupMatcher
	ca.config = authzConfig
	return nil
}

func (ca *configAuthorizer) parse(raw []byte) (*AuthzConfig, error) {
	var c AuthzConfig
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	err := decoder.Decode(&c)
	// XXX io.EOF is returned for an empty file
	if err != nil {
		return nil, err
	}
	// XXX should add some validation here probably
	// return &c, c.Validate()
	return &c, nil
}

func (ca *configAuthorizer) parseConfig(path string) (*AuthzConfig, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error loading AuthzConfig file %q: %v", path, err)
	}
	c, err := ca.parse(b)
	if err != nil {
		return nil, fmt.Errorf("errors while parsing AuthzConfig file %q: %v", path, err)
	}

	return c, nil
}

func (ca *configAuthorizer) Authorize(r *http.Request, user *authenticator.User) (bool, string, error) {
	host := r.Host

	ca.lock.RLock()
	allowedGroups, ok := ca.groupMatcher[host]
	ca.lock.RUnlock()
	// no groups specified for the host, allow the request
	if !ok {
		// TODO make this default behavior configurable
		return true, "", nil
	}
	for _, g := range user.Groups {
		if _, allowed := allowedGroups[g]; allowed {
			log.Infof("authorization success: host=%s user=%s matchedGroup=%s ", host, user.Name, g)
			return true, "", nil
		}
	}
	// XXX think about how to better have groupMatcher + list available to print
	// consider in relation to reloading the authzConfig.
	// or do some async update?
	// do we update config + matcher atomically
	// XXX where to syncronhize with mutex?
	groupsList := ca.config.Rules[host].Groups
	reason := fmt.Sprintf("access to host %q requires membership in one of ([%s])", host, strings.Join(groupsList, ","))
	return false, reason, nil
}
