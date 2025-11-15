#!/usr/bin/env bash

configure_pam() {
  apt install -y libpam-pwquality libpam-modules libpam-modules-bin &>/dev/null
  
  sed -i '/pam_pwquality.so/d' /etc/pam.d/common-password &>/dev/null
  sed -i '/pam_unix.so/i password requisite pam_pwquality.so retry=3 minlen=12 maxrepeat=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 difok=3 reject_username enforce_for_root' /etc/pam.d/common-password &>/dev/null

  sed -i '/pam_pwhistory.so/d' /etc/pam.d/common-password &>/dev/null
  sed -i '/pam_unix.so/a password requisite pam_pwhistory.so remember=5 enforce_for_root use_authtok' /etc/pam.d/common-password &>/dev/null
}

configure_pam
