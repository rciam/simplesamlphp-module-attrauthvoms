<?php

/**
 * COmanage DB authproc filter.
 *
 * Example configuration:
 *
 *    authproc = array(
 *       ...
 *       61 => array(
 *           'class' => 'attrauthvoms:COmanageDbClientCertEntitlement',
 *           'userIdAttribute' => 'distinguishedName',
 *           'attributeName' => 'certEntitlement',
 *           'blacklist' => array(
 *               'https://aai-dev.egi.eu/registry/shibboleth',
 *               'https://snf-766637.vm.okeanos.grnet.gr/Shibboleth.sso/Metadata',
 *               'https://am02.pilots.aarc-project.eu/shibboleth',
 *           ),
 *           'defaultRoles' => array(
 *               'member',
 *               'vm_operator'
 *           ),
 *           'voBlacklist' => array(
 *               'vo.example01.org',
 *               'vo.example02.org',
 *           ),
 *       ),
 *
 * @author Nicolas Liampotis <nliam@grnet.gr>
 */
class sspmod_attrauthvoms_Auth_Process_COmanageDbClientCertEntitlement extends SimpleSAML_Auth_ProcessingFilter
{
    // List of SP entity IDs that should be excluded from this filter.
    private $blacklist = array();

    private $userIdAttribute = 'distinguishedName';

    private $attributeName = 'certEntitlement';

    private $certificateQuery = 'SELECT'
        . ' DISTINCT(subject),'
        . ' issuer'
        . ' FROM cm_certs'
        . ' WHERE cert_id IS NULL'
        . ' AND NOT deleted'
        . ' AND subject IN {SUBJECTDNS}'
        . ' GROUP BY subject,'
        . ' issuer';

    private $voQuery = 'SELECT'
        . ' DISTINCT(vo_id)'
        . ' FROM :tableName'
        . ' WHERE'
        . ' subject = :subject';

    // List of VO names that should be excluded from entitlements.
    private $voBlacklist = array();

    private $defaultRoles = array();

    private $tableNames = array();

    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);
        assert('is_array($config)');

        if (array_key_exists('userIdAttribute', $config)) {
            if (!is_string($config['userIdAttribute'])) {
                SimpleSAML_Logger::error(
                    "[attrauthvoms][CertEntitlement] Configuration error: 'userIdAttribute' not a string literal");
                throw new SimpleSAML_Error_Exception(
                    "attrauthvoms configuration error: 'userIdAttribute' not a string literal");
            }
            $this->userIdAttribute = $config['userIdAttribute'];
        }

        if (array_key_exists('attributeName', $config)) {
            if (!is_string($config['attributeName'])) {
                SimpleSAML_Logger::error(
                    "[attrauthvoms][CertEntitlement] Configuration error: 'attributeName' not a string literal");
                throw new SimpleSAML_Error_Exception(
                    "attrauthvoms configuration error: 'attributeName' not a string literal");
            }
            $this->attributeName = $config['attributeName'];
        }

        if (array_key_exists('blacklist', $config)) {
            if (!is_array($config['blacklist'])) {
                SimpleSAML_Logger::error(
                    "[attrauthvoms][CertEntitlement] Configuration error: 'blacklist' not an array");
                throw new SimpleSAML_Error_Exception(
                    "attrauthvoms configuration error: 'blacklist' not an array");
            }
            $this->blacklist = $config['blacklist'];
        }

        if (array_key_exists('voBlacklist', $config)) {
            if (!is_array($config['voBlacklist'])) {
                SimpleSAML_Logger::error(
                    "[attrauthcomanage][CertEntitlement] Configuration error: 'voBlacklist' not an array");
                throw new SimpleSAML_Error_Exception(
                    "attrauthcomanage configuration error: 'voBlacklist' not an array");
            }
            $this->voBlacklist = $config['voBlacklist'];
        }

        if (array_key_exists('defaultRoles', $config)) {
            if (!is_array($config['defaultRoles'])) {
                SimpleSAML_Logger::error(
                    "[attrauthcomanage][CertEntitlement] Configuration error: 'defaultRoles' not an array");
                throw new SimpleSAML_Error_Exception(
                    "attrauthcomanage configuration error: 'defaultRoles' not an array");
            }
            $this->defaultRoles = $config['defaultRoles'];
        }

        if (array_key_exists('tableNames', $config)) {
            if (!is_array($config['tableNames'])) {
                SimpleSAML_Logger::error(
                    "[attrauthcomanage][CertEntitlement] Configuration error: 'tableNames' not an array");
                throw new SimpleSAML_Error_Exception(
                    "attrauthcomanage configuration error: 'tableNames' not an array");
            }
            $this->tableNames = $config['tableNames'];
        }
    }

    public function process(&$state)
    {
        try {
            assert(is_array($state));
            if (isset($state['SPMetadata']['entityid']) && in_array($state['SPMetadata']['entityid'], $this->blacklist, true)) {
                SimpleSAML_Logger::debug(
                    "[attrauthvoms][CertEntitlement] process: Skipping blacklisted SP "
                    . var_export($state['SPMetadata']['entityid'], true));
                return;
            }
            if (empty($state['Attributes'][$this->userIdAttribute])) {
                SimpleSAML_Logger::debug(
                    "[attrauthvoms][CertEntitlement] process: Skipping user with no '"
                    . var_export($this->userIdAttribute, true). "' attribute");
                return;
            }
            $userIds = $state['Attributes'][$this->userIdAttribute];
            $userCertificates = $this->getCertificates($userIds);
            $certEntitlements = [];
            $totalVos = [];
            foreach ($userCertificates as $certificate) {
                foreach ($this->tableNames as $tableName) {
                    $vos = $this->getVOs($certificate['subject'], $tableName);
                    $totalVos = array_merge($totalVos, $vos);
                }
                SimpleSAML_Logger::debug("[attrauthvoms][CertEntitlement]: vos=" . var_export($totalVos, true));
                foreach ($totalVos as $vo) {
                    SimpleSAML_Logger::debug("[attrauthvoms][CertEntitlement]: vo=" . var_export($vo, true));
                    if (empty($vo['vo_id']) || in_array($vo['vo_id'], $this->voBlacklist, true)) {
                        continue;
                    }
                    if (strpos($vo['vo_id'], ":role=") !== false) {
                        $fqan = explode(":role=", $vo['vo_id']);
                        $entitlement =
                            "urn:mace:egi.eu"               // URN namespace
                            . ":group:"                     // group
                            . urlencode($fqan[0]) . ":"     // VO
                            . "role=" . $fqan[1] . "#"      // role
                            . "aai.egi.eu";                 // AA FQDN TODO
                    } else {
                        foreach ($this->defaultRoles as $role) {
                            $entitlement =
                                "urn:mace:egi.eu"               // URN namespace
                                . ":group:"                     // group
                                . urlencode($vo['vo_id']) . ":" // VO
                                . "role=" . $role . "#"         // role
                                . "aai.egi.eu";                 // AA FQDN TODO
                        }
                    }
                    $jsonEntitlement= "{"
                        . "\"cert_subject_dn\": \"" . $certificate['subject'] . "\","
                        . "\"cert_iss\": \"" . (empty($certificate['issuer']) ? "IGTF" : $certificate['issuer']) . "\","
                        . "\"eduperson_entitlement\": \"" . $entitlement . "\""
                        . "}";
                    SimpleSAML_Logger::debug("[attrauthvoms][CertEntitlement]: jsonEntitlement=" . var_export($jsonEntitlement, true));
                    array_push($certEntitlements, $jsonEntitlement);
                }
            }
            if (count($certEntitlements) > 0) {
                $jsonString = "{\"cert_entitlement\": [";
                $jsonString .= implode(',', $certEntitlements);
                $jsonString .= "]}";
                SimpleSAML_Logger::debug("[attrauthvoms][CertEntitlement] process: jsonString=" . var_export($jsonString, true));
                $state['Attributes'][$this->attributeName] = array(utf8_encode($jsonString));
            }
        } catch (\Exception $e) {
            $this->showException($e);
        }
    }

    private function getCertificates($userIds)
    {
        SimpleSAML_Logger::debug("[attrauthvoms][CertEntitlement] getVOs: userId="
            . var_export($userIds, true));

        $query = $this->certificateQuery;
        $i = 1;
        $qPart = [];
        foreach ($userIds as $id) {
            $qPart[] = ':subject' . $i++;
        }
        $conditions = '(' . implode(', ', $qPart) . ')';
        $query = str_replace("{SUBJECTDNS}", $conditions, $query);

        $queryParams = [];
        $i = 1;
        foreach ($userIds as $id) {
            $queryParams['subject' . $i++] = array($id, PDO::PARAM_STR);
        }

        $result = array();
        $db = SimpleSAML\Database::getInstance();
        $stmt = $db->read($query, $queryParams);
        if ($stmt->execute()) {
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $result[] = $row;
            }
            SimpleSAML_Logger::debug("[attrauthvoms][CertEntitlement] getVOs: result="
                . var_export($result, true));
            return $result;
        } else {
            throw new Exception('Failed to communicate with COmanage Registry: '.var_export($db->getLastError(), true));
        }

        return $result;
    }

    private function getVOs($userId, $tableName)
    {
        SimpleSAML_Logger::debug("[attrauthvoms][CertEntitlement] getVOs: userId="
            . var_export($userId, true));

        $result = array();
        $db = SimpleSAML\Database::getInstance();
        $queryParams = array(
            'subject' => array($userId, PDO::PARAM_STR),
        );

        $strParams = [
            ':tableName' => $tableName,
        ];
        $query =  strtr($this->voQuery, $strParams);
        $stmt = $db->read($query, $queryParams);
        if ($stmt->execute()) {
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $result[] = $row;
            }
            SimpleSAML_Logger::debug("[attrauthvoms][CertEntitlement] getVOs: result="
                . var_export($result, true));
            return $result;
        } else {
            throw new Exception('Failed to communicate with COmanage Registry: '.var_export($db->getLastError(), true));
        }

        return $result;
    }

    private function showException($e)
    {
        $globalConfig = SimpleSAML_Configuration::getInstance();
        $t = new SimpleSAML_XHTML_Template($globalConfig, 'attrauthvoms:exception.tpl.php');
        $t->data['e'] = $e->getMessage();
        $t->show();
        exit();
    }
}
