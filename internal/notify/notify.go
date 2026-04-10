package notify

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

const ntfyBaseURL = "https://ntfy.sh"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// SendFailure sends a backup failure notification to the configured ntfy.sh topic.
// If topic is empty, it does nothing. Errors are logged but not returned because
// notification delivery is best-effort and should not affect the backup job result.
func SendFailure(topic string, jobID int64, errMsg string) {
	if topic == "" {
		return
	}
	msg := fmt.Sprintf("Backup job %d failed: %s", jobID, errMsg)
	send(topic, "Coldcrypt Backup Failed", msg, "rotating_light")
}

// SendTest sends a test notification to the configured ntfy.sh topic.
// Returns an error if the request fails or the topic is empty.
func SendTest(topic string) error {
	if topic == "" {
		return fmt.Errorf("ntfy_topic is not configured")
	}
	return send(topic, "Coldcrypt Test", "This is a test notification from Coldcrypt.", "white_check_mark")
}

func send(topic, title, message, tags string) error {
	url := ntfyBaseURL + "/" + topic
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(message))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Title", title)
	req.Header.Set("Tags", tags)

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("notify: send to ntfy.sh topic %q failed: %v", topic, err)
		return fmt.Errorf("send notification: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		err := fmt.Errorf("ntfy.sh returned status %d", resp.StatusCode)
		log.Printf("notify: %v", err)
		return err
	}
	return nil
}
