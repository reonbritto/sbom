export interface AttackTechnique {
  id: string;
  name: string;
  tactic: string;
  url: string;
}

export interface AttackMapping {
  cwe: string;
  cweName: string;
  capec: { id: string; name: string }[];
  techniques: AttackTechnique[];
}

const CWE_NAMES: Record<string, string> = {
  '20': 'Improper Input Validation',
  '22': 'Path Traversal',
  '74': 'Injection',
  '78': 'OS Command Injection',
  '79': 'Cross-site Scripting (XSS)',
  '88': 'Argument Injection',
  '89': 'SQL Injection',
  '94': 'Code Injection',
  '119': 'Buffer Errors',
  '120': 'Buffer Overflow',
  '125': 'Out-of-bounds Read',
  '190': 'Integer Overflow',
  '200': 'Information Exposure',
  '209': 'Error Message Information Exposure',
  '250': 'Execution with Unnecessary Privileges',
  '269': 'Improper Privilege Management',
  '276': 'Incorrect Default Permissions',
  '287': 'Improper Authentication',
  '290': 'Authentication Bypass by Spoofing',
  '294': 'Authentication Bypass by Capture-replay',
  '295': 'Improper Certificate Validation',
  '306': 'Missing Authentication',
  '352': 'CSRF',
  '400': 'Uncontrolled Resource Consumption (DoS)',
  '416': 'Use After Free',
  '434': 'Unrestricted File Upload',
  '476': 'NULL Pointer Dereference',
  '502': 'Deserialization of Untrusted Data',
  '521': 'Weak Password Requirements',
  '522': 'Insufficiently Protected Credentials',
  '601': 'Open Redirect',
  '611': 'XML External Entity (XXE)',
  '662': 'Improper Synchronization',
  '732': 'Incorrect Permission Assignment',
  '770': 'Allocation Without Limits',
  '787': 'Out-of-bounds Write',
  '798': 'Hard-coded Credentials',
  '862': 'Missing Authorization',
  '863': 'Incorrect Authorization',
  '915': 'Improper Object Attribute Modification',
  '917': 'Expression Language Injection',
  '918': 'SSRF',
  '1188': 'Insecure Default Initialization',
  '1321': 'Prototype Pollution',
  '1333': 'Inefficient Regex (ReDoS)',
};

const CWE_TO_CAPEC: Record<string, { id: string; name: string }[]> = {
  '20': [{ id: 'CAPEC-153', name: 'Input Data Manipulation' }],
  '22': [{ id: 'CAPEC-126', name: 'Path Traversal' }],
  '74': [{ id: 'CAPEC-242', name: 'Code Injection' }],
  '78': [{ id: 'CAPEC-88', name: 'OS Command Injection' }],
  '79': [{ id: 'CAPEC-63', name: 'Cross-Site Scripting' }, { id: 'CAPEC-591', name: 'Reflected XSS' }],
  '88': [{ id: 'CAPEC-6', name: 'Argument Injection' }],
  '89': [{ id: 'CAPEC-66', name: 'SQL Injection' }],
  '94': [{ id: 'CAPEC-242', name: 'Code Injection' }],
  '119': [{ id: 'CAPEC-100', name: 'Buffer Overflow' }],
  '120': [{ id: 'CAPEC-100', name: 'Buffer Overflow' }],
  '125': [{ id: 'CAPEC-540', name: 'Overread Buffers' }],
  '190': [{ id: 'CAPEC-92', name: 'Forced Integer Overflow' }],
  '200': [{ id: 'CAPEC-118', name: 'Information Gathering' }],
  '250': [{ id: 'CAPEC-69', name: 'Target Programs with Elevated Privileges' }],
  '269': [{ id: 'CAPEC-122', name: 'Privilege Abuse' }],
  '287': [{ id: 'CAPEC-115', name: 'Authentication Bypass' }],
  '290': [{ id: 'CAPEC-94', name: 'Adversary in the Middle' }],
  '294': [{ id: 'CAPEC-60', name: 'Reusing Session IDs' }],
  '295': [{ id: 'CAPEC-475', name: 'Signature Spoofing by Improper Validation' }],
  '306': [{ id: 'CAPEC-115', name: 'Authentication Bypass' }],
  '352': [{ id: 'CAPEC-62', name: 'Cross Site Request Forgery' }],
  '400': [{ id: 'CAPEC-125', name: 'Flooding' }, { id: 'CAPEC-130', name: 'Excessive Allocation' }],
  '416': [{ id: 'CAPEC-540', name: 'Overread Buffers' }],
  '434': [{ id: 'CAPEC-1', name: 'Accessing Functionality Not Properly Constrained by ACLs' }],
  '502': [{ id: 'CAPEC-586', name: 'Object Injection' }],
  '521': [{ id: 'CAPEC-49', name: 'Password Brute Forcing' }],
  '522': [{ id: 'CAPEC-560', name: 'Use of Known Domain Credentials' }],
  '601': [{ id: 'CAPEC-178', name: 'Cross-Site Flashing' }],
  '611': [{ id: 'CAPEC-201', name: 'XML External Entities Blowup' }],
  '732': [{ id: 'CAPEC-1', name: 'ACL Misconfiguration' }],
  '770': [{ id: 'CAPEC-130', name: 'Excessive Allocation' }],
  '787': [{ id: 'CAPEC-100', name: 'Buffer Overflow' }],
  '798': [{ id: 'CAPEC-191', name: 'Read Sensitive Strings Within Executable' }],
  '862': [{ id: 'CAPEC-1', name: 'ACL Misconfiguration' }],
  '863': [{ id: 'CAPEC-1', name: 'ACL Misconfiguration' }],
  '915': [{ id: 'CAPEC-77', name: 'Manipulating User-Controlled Variables' }],
  '917': [{ id: 'CAPEC-242', name: 'Code Injection' }],
  '918': [{ id: 'CAPEC-664', name: 'Server Side Request Forgery' }],
  '1321': [{ id: 'CAPEC-77', name: 'Manipulating User-Controlled Variables' }],
  '1333': [{ id: 'CAPEC-492', name: 'Regular Expression Exponential Blowup' }],
};

const T = (id: string, name: string, tactic: string): AttackTechnique => ({
  id,
  name,
  tactic,
  url: `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`,
});

const CWE_TO_TECHNIQUES: Record<string, AttackTechnique[]> = {
  '20': [T('T1059', 'Command and Scripting Interpreter', 'Execution'), T('T1190', 'Exploit Public-Facing Application', 'Initial Access')],
  '22': [T('T1083', 'File and Directory Discovery', 'Discovery'), T('T1005', 'Data from Local System', 'Collection')],
  '74': [T('T1059', 'Command and Scripting Interpreter', 'Execution')],
  '78': [T('T1059', 'Command and Scripting Interpreter', 'Execution'), T('T1190', 'Exploit Public-Facing Application', 'Initial Access')],
  '79': [T('T1059.007', 'JavaScript', 'Execution'), T('T1539', 'Steal Web Session Cookie', 'Credential Access')],
  '88': [T('T1059', 'Command and Scripting Interpreter', 'Execution')],
  '89': [T('T1190', 'Exploit Public-Facing Application', 'Initial Access'), T('T1213', 'Data from Information Repositories', 'Collection')],
  '94': [T('T1059', 'Command and Scripting Interpreter', 'Execution'), T('T1190', 'Exploit Public-Facing Application', 'Initial Access')],
  '119': [T('T1203', 'Exploitation for Client Execution', 'Execution')],
  '120': [T('T1203', 'Exploitation for Client Execution', 'Execution')],
  '125': [T('T1203', 'Exploitation for Client Execution', 'Execution')],
  '190': [T('T1203', 'Exploitation for Client Execution', 'Execution')],
  '200': [T('T1592', 'Gather Victim Host Information', 'Reconnaissance')],
  '250': [T('T1068', 'Exploitation for Privilege Escalation', 'Privilege Escalation')],
  '269': [T('T1068', 'Exploitation for Privilege Escalation', 'Privilege Escalation'), T('T1078', 'Valid Accounts', 'Defense Evasion')],
  '287': [T('T1078', 'Valid Accounts', 'Initial Access'), T('T1212', 'Exploitation for Credential Access', 'Credential Access')],
  '290': [T('T1557', 'Adversary-in-the-Middle', 'Credential Access')],
  '294': [T('T1550', 'Use Alternate Authentication Material', 'Lateral Movement')],
  '295': [T('T1557', 'Adversary-in-the-Middle', 'Credential Access')],
  '306': [T('T1190', 'Exploit Public-Facing Application', 'Initial Access')],
  '352': [T('T1204', 'User Execution', 'Execution')],
  '400': [T('T1499', 'Endpoint Denial of Service', 'Impact')],
  '416': [T('T1203', 'Exploitation for Client Execution', 'Execution'), T('T1068', 'Exploitation for Privilege Escalation', 'Privilege Escalation')],
  '434': [T('T1505.003', 'Web Shell', 'Persistence')],
  '502': [T('T1190', 'Exploit Public-Facing Application', 'Initial Access'), T('T1059', 'Command and Scripting Interpreter', 'Execution')],
  '521': [T('T1110', 'Brute Force', 'Credential Access')],
  '522': [T('T1552', 'Unsecured Credentials', 'Credential Access')],
  '601': [T('T1566.002', 'Spearphishing Link', 'Initial Access')],
  '611': [T('T1213', 'Data from Information Repositories', 'Collection'), T('T1083', 'File and Directory Discovery', 'Discovery')],
  '732': [T('T1078', 'Valid Accounts', 'Privilege Escalation')],
  '770': [T('T1499', 'Endpoint Denial of Service', 'Impact')],
  '787': [T('T1203', 'Exploitation for Client Execution', 'Execution'), T('T1068', 'Exploitation for Privilege Escalation', 'Privilege Escalation')],
  '798': [T('T1552.001', 'Credentials In Files', 'Credential Access')],
  '862': [T('T1078', 'Valid Accounts', 'Privilege Escalation')],
  '863': [T('T1078', 'Valid Accounts', 'Privilege Escalation')],
  '915': [T('T1190', 'Exploit Public-Facing Application', 'Initial Access')],
  '917': [T('T1059', 'Command and Scripting Interpreter', 'Execution')],
  '918': [T('T1090', 'Proxy', 'Command and Control'), T('T1213', 'Data from Information Repositories', 'Collection')],
  '1321': [T('T1190', 'Exploit Public-Facing Application', 'Initial Access')],
  '1333': [T('T1499', 'Endpoint Denial of Service', 'Impact')],
};

export function mapCweToAttack(cweIds: string[]): AttackMapping[] {
  const out: AttackMapping[] = [];
  const seen = new Set<string>();
  for (const cwe of cweIds) {
    const num = cwe.replace(/^CWE-/i, '');
    if (seen.has(num)) continue;
    seen.add(num);
    const techniques = CWE_TO_TECHNIQUES[num];
    if (!techniques) continue;
    out.push({
      cwe: `CWE-${num}`,
      cweName: CWE_NAMES[num] ?? `Weakness ${num}`,
      capec: CWE_TO_CAPEC[num] ?? [],
      techniques,
    });
  }
  return out;
}

export function uniqueTechniques(mappings: AttackMapping[]): AttackTechnique[] {
  const seen = new Map<string, AttackTechnique>();
  for (const m of mappings) for (const t of m.techniques) seen.set(t.id, t);
  return Array.from(seen.values());
}

export function tacticsCovered(mappings: AttackMapping[]): string[] {
  const set = new Set<string>();
  for (const t of uniqueTechniques(mappings)) set.add(t.tactic);
  return Array.from(set);
}
