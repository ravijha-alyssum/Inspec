# copyright: 2024, The Authors

title "Secure SSH Server Baseline"

# ===================================================================
# Control Group 1: Basic Service Health
# ===================================================================
control 'ssh-service-1.0' do
  impact 1.0
  title 'SSH server must be installed and running'
  desc 'The SSH server provides critical remote access and must be operational.'

  describe service('sshd') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end

# ===================================================================
# Control Group 2: Authentication and Access Control
# ===================================================================
control 'ssh-auth-2.0' do
  impact 0.9
  title 'SSH must enforce secure authentication policies'
  desc 'To prevent unauthorized access, root login and password-based authentication must be disabled.'

  describe sshd_config do
    its('PermitRootLogin') { should eq 'no' }
    its('PasswordAuthentication') { should eq 'no' }
    its('PermitEmptyPasswords') { should eq 'no' }
  end
end

# ===================================================================
# Control Group 3: Protocol and Configuration Security
# ===================================================================
control 'ssh-protocol-3.0' do
  impact 0.7
  title 'SSH must use a secure protocol version'
  desc 'Only SSH Protocol 2 should be used, as Protocol 1 is obsolete and insecure.'

  describe sshd_config do
    its('Protocol') { should eq '2' }
  end
end

# ===================================================================
# Control Group 4: File System Permissions
# ===================================================================
control 'ssh-permissions-4.0' do
  impact 0.5
  title 'SSH configuration file must have secure permissions'
  desc 'The sshd_config file should not be writable by anyone other than the owner to prevent unauthorized modifications.'

  describe file('/etc/ssh/sshd_config') do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('others') }
  end
end

# ===================================================================
# NEW - Control Group 5: Legal Banner and Warnings
# ===================================================================
control 'ssh-banner-5.0' do
  impact 0.9
  title 'A warning banner must be configured'
  desc 'Displaying a legal banner is mandatory for many compliance frameworks to warn against unauthorized access.'

  describe sshd_config do
    # This check ensures the SSH server is configured to display a banner file.
    its('Banner') { should eq '/etc/issue.net' }
  end

  describe file('/etc/issue.net') do
    # This check ensures the banner file actually exists.
    it { should be_file }
    its('content') { should_not be_empty }
  end
end

# ===================================================================
# NEW - Control Group 6: Strong Cryptography
# ===================================================================
control 'ssh-crypto-6.0' do
  impact 0.8
  title 'Use strong cryptographic algorithms'
  desc 'Avoid legacy and weak cryptographic algorithms. This profile checks for a baseline of modern, secure ciphers and MACs.'
  
  # Note: A production profile would have a more exhaustive list.
  # These checks validate that the configuration explicitly defines strong crypto.
  describe sshd_config do
    its('Ciphers') { should match(/aes256-ctr,aes192-ctr,aes128-ctr/) }
    its('MACs') { should match(/hmac-sha2-512,hmac-sha2-256/) }
  end
end

# ===================================================================
# NEW - Control Group 7: Explicit User Access Control
# ===================================================================
control 'ssh-access-7.0' do
  impact 0.9
  title 'SSH access must be restricted to authorized users'
  desc 'Enforce the principle of least privilege by explicitly defining who can log in using AllowUsers.'
  
  # This is a great test for a POC because it will likely FAIL.
  # The default sshd_config allows all users. This control enforces that you
  # MUST have an "AllowUsers" line, demonstrating how InSpec catches insecure defaults.
  describe sshd_config do
    its('AllowUsers') { should_not be_nil }
    its('AllowUsers') { should eq 'testuser' }
  end
end

# ===================================================================
# NEW - Control Group 8: Session Management and Hardening
# ===================================================================
control 'ssh-hardening-8.0' do
  impact 0.6
  title 'Disable unnecessary and risky SSH features'
  desc 'Harden the SSH server by setting idle timeouts and disabling unused features like X11 forwarding.'

  describe sshd_config do
    # Automatically log out idle clients after 15 minutes (900s)
    its('ClientAliveInterval') { should eq '900' }
    
    # Disconnect after 2 idle checks (total 30 minutes)
    its('ClientAliveCountMax') { should eq '2' }
    
    # X11 Forwarding can create security vulnerabilities and should be disabled if not used.
    its('X11Forwarding') { should eq 'no' }
  end
end