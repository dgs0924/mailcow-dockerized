<?php

require_once __DIR__ . '/../../data/web/inc/functions.inc.php';

class LdapMailboxMappingTestQuery {
  public $records;
  public $where_values = array();
  public $get_calls = 0;
  public $first_calls = 0;
  public $limit_value = null;

  public function __construct($records) {
    $this->records = $records;
  }

  public function rawFilter($filter) {
    return $this;
  }

  public function where($field, $operator, $value) {
    $this->where_values[] = array($field, $operator, $value);
    return $this;
  }

  public function select($fields) {
    return $this;
  }

  public function limit($limit) {
    $this->limit_value = $limit;
    return $this;
  }

  public function get() {
    $this->get_calls++;
    return $this->records;
  }

  public function firstOrFail() {
    $this->first_calls++;
    if (count($this->records) === 0) {
      throw new Exception('LDAP entry not found');
    }
    return $this->records[0];
  }
}

class LdapMailboxMappingTestAuth {
  public $attempts = array();
  public $result = true;

  public function attempt($dn, $password) {
    $this->attempts[] = array($dn, $password);
    return $this->result;
  }
}

class LdapMailboxMappingTestProvider {
  public $query;
  public $auth;

  public function __construct($query, $auth) {
    $this->query = $query;
    $this->auth = $auth;
  }

  public function query() {
    return $this->query;
  }

  public function auth() {
    return $this->auth;
  }
}

function mailbox($action, $type, $data = null) {
  global $mailbox_calls;
  $mailbox_calls[] = array($action, $type, $data);
  return true;
}

require_once __DIR__ . '/../../data/web/inc/functions.auth.inc.php';

$failures = 0;
function assert_same($expected, $actual, $message) {
  global $failures;
  if ($expected !== $actual) {
    $failures++;
    fwrite(STDERR, "FAIL: " . $message . "\nExpected: " . var_export($expected, true) . "\nActual: " . var_export($actual, true) . "\n");
  }
}

function ldap_record($mobile) {
  return array(
    'mobile' => array($mobile),
    'department' => array('staff'),
    'displayname' => array('LDAP Test User'),
    'dn' => 'cn=ldap-test-user,dc=example,dc=test'
  );
}

function configure_ldap_test($records, $mailbox_domain) {
  global $iam_provider, $iam_settings, $mailbox_calls, $test_query, $test_auth;
  $test_query = new LdapMailboxMappingTestQuery($records);
  $test_auth = new LdapMailboxMappingTestAuth();
  $iam_provider = new LdapMailboxMappingTestProvider($test_query, $test_auth);
  $iam_settings = array(
    'username_field' => 'mobile',
    'attribute_field' => 'department',
    'mappers' => array('staff'),
    'templates' => array('ldap-template'),
    'mailbox_domain' => $mailbox_domain,
    'login_provisioning' => 1
  );
  $mailbox_calls = array();
  $_SESSION = array();
}

assert_same('cqzhgz.cn', ldap_mailbox_domain(array('mailbox_domain' => ' CQZHGZ.CN ')), 'configured mailbox domain is normalized');
assert_same(false, ldap_mailbox_domain(array('mailbox_domain' => 'cqzhgz.cn/invalid')), 'invalid configured mailbox domain is rejected');
assert_same(false, ldap_mailbox_domain(array('mailbox_domain' => '例子.公司')), 'non-ASCII configured mailbox domain is rejected');
assert_same('13800138000@cqzhgz.cn', ldap_mailbox_username('13800138000', array('mailbox_domain' => 'cqzhgz.cn')), 'LDAP mobile is mapped to a mailbox address');
assert_same('13800138000', ldap_username_from_mailbox_username('13800138000@cqzhgz.cn', array('mailbox_domain' => 'cqzhgz.cn')), 'mapped mailbox login resolves to LDAP mobile');
assert_same(false, ldap_username_from_mailbox_username('13800138000@wrong.example', array('mailbox_domain' => 'cqzhgz.cn')), 'wrong mailbox domain is rejected before LDAP lookup');
assert_same('legacy@example.test', ldap_username_from_mailbox_username('legacy@example.test', array('mailbox_domain' => '')), 'empty mailbox domain preserves legacy LDAP lookup');
$duplicate_mailbox_counts = ldap_mapped_mailbox_username_counts(array(ldap_record('13800138000'), ldap_record('13800138000')), array('username_field' => 'mobile', 'mailbox_domain' => 'cqzhgz.cn'));
assert_same(2, $duplicate_mailbox_counts['13800138000@cqzhgz.cn'], 'sync preprocessing detects every duplicate mapped mailbox before writes');
$invalid_mailbox_counts = ldap_mapped_mailbox_username_counts(array(ldap_record('invalid mobile')), array('username_field' => 'mobile', 'mailbox_domain' => 'cqzhgz.cn'));
assert_same(array(), $invalid_mailbox_counts, 'sync preprocessing skips LDAP values that cannot map to a mailbox');

configure_ldap_test(array(ldap_record('13800138000')), 'cqzhgz.cn');
assert_same('user', ldap_mbox_login('13800138000@cqzhgz.cn', 'secret', array('is_internal' => true)), 'mapped LDAP login succeeds');
assert_same(array(array('mobile', '=', '13800138000')), $test_query->where_values, 'mapped LDAP login queries by mobile');
assert_same(2, $test_query->limit_value, 'mapped LDAP login limits duplicate detection to two entries');
assert_same(1, count($test_auth->attempts), 'mapped LDAP login authenticates the resolved LDAP entry');
assert_same('13800138000@cqzhgz.cn', $mailbox_calls[0][2]['username'], 'mapped LDAP login updates the mapped mailbox identity');

configure_ldap_test(array(ldap_record('13800138000')), 'cqzhgz.cn');
assert_same('user', ldap_mbox_login('13800138000@cqzhgz.cn', 'secret', array('is_internal' => true, 'create' => true)), 'mapped LDAP login provisions a mailbox');
assert_same('add', $mailbox_calls[0][0], 'mapped LDAP provisioning creates a mailbox');
assert_same('mailbox_from_template', $mailbox_calls[0][1], 'mapped LDAP provisioning uses the mailbox template path');
assert_same('cqzhgz.cn', $mailbox_calls[0][2]['domain'], 'mapped LDAP provisioning sets the configured mailbox domain');
assert_same('13800138000', $mailbox_calls[0][2]['local_part'], 'mapped LDAP provisioning sets the LDAP mobile as the local part');
assert_same('ldap', $mailbox_calls[0][2]['authsource'], 'mapped LDAP provisioning keeps LDAP as the mailbox auth source');
assert_same('ldap-template', $mailbox_calls[0][2]['template'], 'mapped LDAP provisioning selects the LDAP template');

configure_ldap_test(array(ldap_record('13800138000')), 'cqzhgz.cn');
$test_auth->result = false;
assert_same(false, ldap_mbox_login('13800138000@cqzhgz.cn', 'wrong-secret', array('is_internal' => true, 'create' => true)), 'failed LDAP bind is rejected');
assert_same(array(), $mailbox_calls, 'failed LDAP bind cannot create or edit a mailbox');

configure_ldap_test(array(ldap_record('13800138000')), 'cqzhgz.cn');
$iam_settings['login_provisioning'] = 0;
assert_same(false, ldap_mbox_login('13800138000@cqzhgz.cn', 'secret', array('is_internal' => true, 'create' => true)), 'disabled login provisioning is enforced');
assert_same(array(), $mailbox_calls, 'disabled login provisioning cannot create a mailbox');

configure_ldap_test(array(ldap_record('13800138000')), 'cqzhgz.cn');
assert_same(false, ldap_mbox_login('13800138000@wrong.example', 'secret', array('is_internal' => true)), 'wrong-domain login is rejected');
assert_same(array(), $test_query->where_values, 'wrong-domain login does not query LDAP');

configure_ldap_test(array(ldap_record('13900139000')), 'cqzhgz.cn');
assert_same(false, ldap_mbox_login('13800138000@cqzhgz.cn', 'secret', array('is_internal' => true)), 'LDAP identity mismatch is rejected');
assert_same(0, count($test_auth->attempts), 'LDAP identity mismatch is rejected before password bind');

configure_ldap_test(array(ldap_record('13800138000'), ldap_record('13800138000')), 'cqzhgz.cn');
assert_same(false, ldap_mbox_login('13800138000@cqzhgz.cn', 'secret', array('is_internal' => true)), 'ambiguous LDAP mobile is rejected');
assert_same(0, count($test_auth->attempts), 'ambiguous LDAP mobile is rejected before password bind');

configure_ldap_test(array(ldap_record('legacy@example.test')), '');
assert_same('user', ldap_mbox_login('legacy@example.test', 'secret', array('is_internal' => true)), 'empty domain keeps the legacy full-email LDAP login path');
assert_same(array(array('mobile', '=', 'legacy@example.test')), $test_query->where_values, 'legacy login still queries LDAP with the full input');
assert_same(1, $test_query->first_calls, 'legacy login keeps first-match LDAP behavior');

if ($failures > 0) {
  exit(1);
}

echo "LDAP mailbox mapping tests passed\n";
