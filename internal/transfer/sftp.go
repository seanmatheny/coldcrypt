package transfer

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Client wraps an SFTP connection.
type Client struct {
	sshConn *ssh.Client
	sftp    *sftp.Client
}

// NewClient creates a new SFTP client using SSH key or password authentication.
func NewClient(host string, port int, user, keyPath, password string) (*Client, error) {
	var authMethods []ssh.AuthMethod

	if keyPath != "" {
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("read ssh key: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("parse ssh key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if password != "" {
		authMethods = append(authMethods, ssh.Password(password))
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no SSH authentication method configured (set remote_key_path or remote_password)")
	}

	sshCfg := &ssh.ClientConfig{
		User: user,
		Auth: authMethods,
		// Accept any host key. For production, use a known_hosts file.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
		Timeout:         30_000_000_000, // 30 seconds
	}

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", addr, err)
	}

	sftpClient, err := sftp.NewClient(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("sftp new client: %w", err)
	}

	return &Client{sshConn: conn, sftp: sftpClient}, nil
}

// Close closes the SFTP and SSH connections.
func (c *Client) Close() error {
	if err := c.sftp.Close(); err != nil {
		return err
	}
	return c.sshConn.Close()
}

// UploadBlob uploads data from r to the remote path/blobID.
func (c *Client) UploadBlob(remotePath, blobID string, r io.Reader) error {
	dest := filepath.Join(remotePath, blobID)
	f, err := c.sftp.Create(dest)
	if err != nil {
		return fmt.Errorf("sftp create %s: %w", dest, err)
	}
	defer f.Close()
	if _, err := io.Copy(f, r); err != nil {
		return fmt.Errorf("sftp write %s: %w", dest, err)
	}
	return nil
}

// DeleteBlob removes a remote blob by ID.
func (c *Client) DeleteBlob(remotePath, blobID string) error {
	dest := filepath.Join(remotePath, blobID)
	return c.sftp.Remove(dest)
}

// DownloadBlob downloads a remote blob and returns a ReadCloser.
func (c *Client) DownloadBlob(remotePath, blobID string) (io.ReadCloser, error) {
	src := filepath.Join(remotePath, blobID)
	f, err := c.sftp.Open(src)
	if err != nil {
		return nil, fmt.Errorf("sftp open %s: %w", src, err)
	}
	return f, nil
}

// EnsureDir creates remote directories recursively if they don't exist.
func (c *Client) EnsureDir(path string) error {
	return c.sftp.MkdirAll(path)
}
