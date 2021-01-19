<?php

namespace SimpleSAML\Module\attrauthvoms\Auth\Process;

/**
 * COmanage DB authproc filter.
 *
 * Example configuration:
 *
 *    authproc = array(
 *       ...
 *       '60' => array(
 *            'class' => 'attrauthvoms:COmanageDbClient',
 *            'userIdAttribute' => 'distinguishedName',
 *       ),
 *
 * @author Nicolas Liampotis <nliam@grnet.gr>
 */
class COmanageDbClient extends SimpleSAML\Auth\ProcessingFilter
{
    // List of SP entity IDs that should be excluded from this filter.
    private $blacklist = array();

    private $userIdAttribute = 'distinguishedName';

    private $voQuery = 'SELECT'
        . ' DISTINCT(vo_id)'
        . ' FROM voms_members'
        . ' WHERE'
        . ' subject = :subject';

    // List of VO names that should be excluded from entitlements.
    private $voBlacklist = array();

    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);
        assert('is_array($config)');

        if (array_key_exists('userIdAttribute', $config)) {
            if (!is_string($config['userIdAttribute'])) {
                SimpleSAML\Logger::error(
                    "[attrauthvoms] Configuration error: 'userIdAttribute' not a string literal");
                throw new SimpleSAML\Error\Exception(
                    "attrauthvoms configuration error: 'userIdAttribute' not a string literal");
            }
            $this->userIdAttribute = $config['userIdAttribute'];
        }

        if (array_key_exists('blacklist', $config)) {
            if (!is_array($config['blacklist'])) {
                SimpleSAML\Logger::error(
                    "[attrauthvoms] Configuration error: 'blacklist' not an array");
                throw new SimpleSAML\Error\Exception(
                    "attrauthvoms configuration error: 'blacklist' not an array");
            }
            $this->blacklist = $config['blacklist'];
        }
        if (array_key_exists('voBlacklist', $config)) {
            if (!is_array($config['voBlacklist'])) {
                SimpleSAML\Logger::error(
                    "[attrauthcomanage] Configuration error: 'voBlacklist' not an array");
                throw new SimpleSAML\Error\Exception(
                    "attrauthcomanage configuration error: 'voBlacklist' not an array");
            }
            $this->voBlacklist = $config['voBlacklist'];
        }
    }

    public function process(&$state)
    {
        try {
            assert('is_array($state)');
            if (isset($state['SPMetadata']['entityid']) && in_array($state['SPMetadata']['entityid'], $this->blacklist, true)) {
                SimpleSAML\Logger::debug(
                    "[attrauthvoms] process: Skipping blacklisted SP "
                    . var_export($state['SPMetadata']['entityid'], true));
                return;
            }
            if (empty($state['Attributes'][$this->userIdAttribute])) {
                SimpleSAML\Logger::debug(
                    "[attrauthvoms] process: Skipping user with no '"
                    . var_export($this->userIdAttribute, true). "' attribute");
                return;
            }
            $userIds = $state['Attributes'][$this->userIdAttribute];
            foreach ($userIds as $userId) {
                $vos = $this->getVOs($userId);
                foreach ($vos as $vo) {
                    if (empty($vo['vo_id']) || in_array($vo['vo_id'], $this->voBlacklist, true)) {
                        continue;
                    }
                    $roles = array("member", "vm_operator"); // TODO
                    if (empty($state['Attributes']['eduPersonEntitlement'])) {
                        $state['Attributes']['eduPersonEntitlement'] = array();
                    }
                    foreach ($roles as $role) {
                        $entitlement =
                            "urn:mace:egi.eu:group:"        // URN namespace
                            . urlencode($vo['vo_id']) . ":" // VO
                            . "role=" . $role               // role
                            . "#aai.egi.eu";                // AA FQDN TODO
                        if (!in_array($entitlement, $state['Attributes']['eduPersonEntitlement'], true)) {
                            $state['Attributes']['eduPersonEntitlement'][] = $entitlement;
                        }
                    }
                }
            }
        } catch (\Exception $e) {
            $this->showException($e);
        }
    }

    private function getVOs($userId)
    {
        SimpleSAML\Logger::debug("[attrauthvoms] getVOs: userId="
            . var_export($userId, true));

        $result = array();
        $db = SimpleSAML\Database::getInstance();
        $queryParams = array(
            'subject' => array($userId, PDO::PARAM_STR),
        );
        $stmt = $db->read($this->voQuery, $queryParams);
        if ($stmt->execute()) {
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $result[] = $row;
            }
            SimpleSAML\Logger::debug("[attrauthvoms] getVOs: result="
                . var_export($result, true));
            return $result;
        } else {
            throw new Exception('Failed to communicate with COmanage Registry: '.var_export($db->getLastError(), true));
        }

        return $result;
    }

    private function showException($e)
    {
        $globalConfig = SimpleSAML\Configuration::getInstance();
        $t = new SimpleSAML\XHTML\Template($globalConfig, 'attrauthvoms:exception.tpl.php');
        $t->data['e'] = $e->getMessage();
        $t->show();
        exit();
    }
}
