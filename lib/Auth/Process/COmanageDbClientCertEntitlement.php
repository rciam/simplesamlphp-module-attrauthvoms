<?php

namespace SimpleSAML\Module\attrauthvoms\Auth\Process;

use PDO;
use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\XHTML\Template;

/**
 * COmanage DB authproc filter.
 *
 * Example configuration:
 *
 *    authproc = [
 *       ...
 *       61 => [
 *           'class' => 'attrauthvoms:COmanageDbClientCertEntitlement',
 *           'userIdAttribute' => 'distinguishedName',
 *           'attributeName' => 'certEntitlement',
 *           'spWhitelist' => [
 *               'https://aai-dev.egi.eu/registry/shibboleth',
 *               'https://snf-766637.vm.okeanos.grnet.gr/Shibboleth.sso/Metadata',
 *               'https://am02.pilots.aarc-project.eu/shibboleth',
 *           ],
 *           'defaultRoles' => [
 *               'member',
 *               'vm_operator'
 *           ],
 *           'voBlacklist' => [
 *               'vo.example01.org',
 *               'vo.example02.org',
 *           ],
 *           'role_urn_namespace' => 'urn:mace:example.org',
 *           'role_authority' => 'www.example.org',
 *           'defaultIssuerDn' => 'IGTF',
 *       ],
 *
 * @author Nicolas Liampotis <nliam@grnet.gr>
 * @author nikosev <nikos.ev@hotmail.com>
 */
class COmanageDbClientCertEntitlement extends ProcessingFilter
{
    // List of SP entity IDs that should be excluded from this filter.
    private $spWhitelist = null;

    private $userIdAttribute = 'distinguishedName';

    private $attributeName = 'certEntitlement';

    private $voQuery = 'SELECT'
        . ' subject,'
        . ' issuer,'
        . ' vo_id'
        . ' FROM :tableName'
        . ' WHERE'
        . ' subject = :subject';

    // List of VO names that should be excluded from entitlements.
    private $voBlacklist = [];

    private $defaultRoles = [];

    private $allowEmptyRole = false;

    private $tableNames = [];

    private $roleUrnNamespace;

    private $roleAuthority;

    private $defaultIssuerDn;

    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);
        assert('is_array($config)');

        if (array_key_exists('userIdAttribute', $config)) {
            if (!is_string($config['userIdAttribute'])) {
                Logger::error(
                    "[attrauthvoms][CertEntitlement] Configuration error: 'userIdAttribute' not a string literal"
                );
                throw new Error\Exception(
                    "attrauthvoms configuration error: 'userIdAttribute' not a string literal"
                );
            }
            $this->userIdAttribute = $config['userIdAttribute'];
        }

        if (array_key_exists('attributeName', $config)) {
            if (!is_string($config['attributeName'])) {
                Logger::error(
                    "[attrauthvoms][CertEntitlement] Configuration error: 'attributeName' not a string literal"
                );
                throw new Error\Exception(
                    "attrauthvoms configuration error: 'attributeName' not a string literal"
                );
            }
            $this->attributeName = $config['attributeName'];
        }

        if (array_key_exists('spWhitelist', $config)) {
            if (!is_array($config['spWhitelist'])) {
                Logger::error(
                    "[attrauthvoms][CertEntitlement] Configuration error: 'spWhitelist' not an array"
                );
                throw new Error\Exception(
                    "attrauthvoms configuration error: 'spWhitelist' not an array"
                );
            }
            $this->spWhitelist = $config['spWhitelist'];
        }

        if (array_key_exists('voBlacklist', $config)) {
            if (!is_array($config['voBlacklist'])) {
                Logger::error(
                    "[attrauthcomanage][CertEntitlement] Configuration error: 'voBlacklist' not an array"
                );
                throw new Error\Exception(
                    "attrauthcomanage configuration error: 'voBlacklist' not an array"
                );
            }
            $this->voBlacklist = $config['voBlacklist'];
        }

        if (array_key_exists('defaultRoles', $config)) {
            if (!is_array($config['defaultRoles'])) {
                Logger::error(
                    "[attrauthcomanage][CertEntitlement] Configuration error: 'defaultRoles' not an array"
                );
                throw new Error\Exception(
                    "attrauthcomanage configuration error: 'defaultRoles' not an array"
                );
            }
            $this->defaultRoles = $config['defaultRoles'];
        }

        if (array_key_exists('tableNames', $config)) {
            if (!is_array($config['tableNames'])) {
                Logger::error(
                    "[attrauthcomanage][CertEntitlement] Configuration error: 'tableNames' not an array"
                );
                throw new Error\Exception(
                    "attrauthcomanage configuration error: 'tableNames' not an array"
                );
            }
            $this->tableNames = $config['tableNames'];
        }

        if (array_key_exists('role_urn_namespace', $config)) {
            if (!is_string($config['role_urn_namespace'])) {
                Logger::error(
                    "[attrauthvoms][CertEntitlement] Configuration error: 'role_urn_namespace' not a string literal"
                );
                throw new Error\Exception(
                    "attrauthvoms configuration error: 'role_urn_namespace' not a string literal"
                );
            }
            $this->roleUrnNamespace = $config['role_urn_namespace'];
        }

        if (array_key_exists('role_authority', $config)) {
            if (!is_string($config['role_authority'])) {
                Logger::error(
                    "[attrauthvoms][CertEntitlement] Configuration error: 'role_authority' not a string literal"
                );
                throw new Error\Exception(
                    "attrauthvoms configuration error: 'role_authority' not a string literal"
                );
            }
            $this->roleAuthority = $config['role_authority'];
        }

        if (array_key_exists('defaultIssuerDn', $config)) {
            if (!is_string($config['defaultIssuerDn'])) {
                Logger::error(
                    "[attrauthvoms][CertEntitlement] Configuration error: 'defaultIssuerDn' not a string literal"
                );
                throw new Error\Exception(
                    "attrauthvoms configuration error: 'defaultIssuerDn' not a string literal"
                );
            }
            $this->defaultIssuerDn = $config['defaultIssuerDn'];
        }

        if (array_key_exists('allowEmptyRole', $config)) {
            if (!is_bool($config['allowEmptyRole'])) {
                Logger::error(
                    "[attrauthvoms][CertEntitlement] Configuration error: 'allowEmptyRole' not boolean"
                );
                throw new Error\Exception(
                    "attrauthvoms configuration error: 'allowEmptyRole' not a string literal"
                );
            }
            $this->allowEmptyRole = $config['allowEmptyRole'];
        }
    }

    public function process(&$state)
    {
        try {
            assert(is_array($state));
            if (
                isset($state['SPMetadata']['entityid'])
                && isset($this->spWhitelist)
                && !in_array($state['SPMetadata']['entityid'], $this->spWhitelist, true)
            ) {
                Logger::debug(
                    "[attrauthvoms][CertEntitlement] process: Skipping not whitelisted SP "
                    . var_export($state['SPMetadata']['entityid'], true)
                );
                return;
            }
            if (empty($state['Attributes'][$this->userIdAttribute])) {
                Logger::debug(
                    "[attrauthvoms][CertEntitlement] process: Skipping user with no '"
                    . var_export($this->userIdAttribute, true) . "' attribute"
                );
                return;
            }
            $userIds = $state['Attributes'][$this->userIdAttribute];
            $certEntitlements = [];
            foreach ($userIds as $userId) {
                $totalVos = [];
                foreach ($this->tableNames as $tableName) {
                    $vos = $this->getVOs($userId, $tableName);
                    $totalVos = array_merge($totalVos, $vos);
                }
                Logger::debug("[attrauthvoms][CertEntitlement]: vos=" . var_export($totalVos, true));
                foreach ($totalVos as $vo) {
                    Logger::debug("[attrauthvoms][CertEntitlement]: vo=" . var_export($vo, true));
                    if (empty($vo['vo_id']) || in_array($vo['vo_id'], $this->voBlacklist, true)) {
                        continue;
                    }
                    if (strpos($vo['vo_id'], ":role=") !== false) {
                        $fqan = explode(":role=", $vo['vo_id']);
                        $entitlement =
                            $this->roleUrnNamespace                 // URN namespace
                            . ":group:"                             // group
                            . urlencode($fqan[0]) . ":"             // VO
                            . "role=" . urlencode($fqan[1]) . "#"   // role
                            . $this->roleAuthority;                 // AA FQDN TODO
                        $certEntitlements = $this->getJsonEntitlement(
                            $certEntitlements,
                            $entitlement,
                            $vo['subject'],
                            $vo['issuer']
                        );
                    } else {
                        foreach ($this->defaultRoles as $role) {
                            $entitlement =
                                $this->roleUrnNamespace             // URN namespace
                                . ":group:"                         // group
                                . urlencode($vo['vo_id']) . ":"     // VO
                                . "role=" . urlencode($role) . "#"  // role
                                . $this->roleAuthority;             // AA FQDN TODO
                            $certEntitlements = $this->getJsonEntitlement(
                                $certEntitlements,
                                $entitlement,
                                $vo['subject'],
                                $vo['issuer']
                            );
                        }
                        // create entitlement without role
                        if ($this->allowEmptyRole) {
                            $entitlement =
                                $this->roleUrnNamespace             // URN namespace
                                . ":group:"                         // group
                                . urlencode($vo['vo_id']) . "#"     // VO
                                . $this->roleAuthority;             // AA FQDN TODO
                            $certEntitlements = $this->getJsonEntitlement(
                                $certEntitlements,
                                $entitlement,
                                $vo['subject'],
                                $vo['issuer']
                            );
                        }
                    }
                }
            }
            if (count($certEntitlements) > 0) {
                $jsonString = "[";
                $jsonString .= implode(',', $certEntitlements);
                $jsonString .= "]";
                Logger::debug("[attrauthvoms][CertEntitlement] process: jsonString=" . var_export($jsonString, true));
                $state['Attributes'][$this->attributeName] = [utf8_encode($jsonString)];
            }
        } catch (\Exception $e) {
            $this->showException($e);
        }
    }

    private function getVOs($userId, $tableName)
    {
        Logger::debug("[attrauthvoms][CertEntitlement] getVOs: userId="
            . var_export($userId, true));

        $result = [];
        $db = Database::getInstance();
        $queryParams = [
            'subject' => [$userId, PDO::PARAM_STR],
        ];

        $strParams = [
            ':tableName' => $tableName,
        ];
        $query =  strtr($this->voQuery, $strParams);
        $stmt = $db->read($query, $queryParams);
        if ($stmt->execute()) {
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $result[] = $row;
            }
            Logger::debug("[attrauthvoms][CertEntitlement] getVOs: result="
                . var_export($result, true));
            return $result;
        } else {
            throw new Error\Exception(
                'Failed to communicate with COmanage Registry: ' . var_export($db->getLastError(), true)
            );
        }

        return $result;
    }

    private function getJsonEntitlement($entitlementArray, $entitlementValue, $subjectDn, $issuerDn)
    {
        $jsonEntitlement = "{"
            . "\"cert_subject_dn\": \"" . $subjectDn . "\","
            . "\"cert_iss\": \"" . (empty($issuerDn) ? $this->defaultIssuerDn : $issuerDn) . "\","
            . "\"eduperson_entitlement\": \"" . $entitlementValue . "\""
            . "}";
        Logger::debug("[attrauthvoms][CertEntitlement]: jsonEntitlement=" . var_export($jsonEntitlement, true));
        return array_merge($entitlementArray, [$jsonEntitlement]);
    }

    private function showException($e)
    {
        $globalConfig = Configuration::getInstance();
        $t = new Template($globalConfig, 'attrauthvoms:exception.tpl.php');
        $t->data['e'] = $e->getMessage();
        $t->show();
        exit();
    }
}
