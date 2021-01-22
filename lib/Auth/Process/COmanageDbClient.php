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
 *       '60' => [
 *            'class' => 'attrauthvoms:COmanageDbClient',
 *            'userIdAttribute' => 'distinguishedName',
 *       ],
 *
 * @author Nicolas Liampotis <nliam@grnet.gr>
 */
class COmanageDbClient extends ProcessingFilter
{
    // List of SP entity IDs that should be excluded from this filter.
    private $blacklist = [];

    private $userIdAttribute = 'distinguishedName';

    private $voQuery = 'SELECT'
        . ' DISTINCT(vo_id)'
        . ' FROM voms_members'
        . ' WHERE'
        . ' subject = :subject';

    // List of VO names that should be excluded from entitlements.
    private $voBlacklist = [];

    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);
        assert('is_array($config)');

        if (array_key_exists('userIdAttribute', $config)) {
            if (!is_string($config['userIdAttribute'])) {
                Logger::error(
                    "[attrauthvoms] Configuration error: 'userIdAttribute' not a string literal"
                );
                throw new Error\Exception(
                    "attrauthvoms configuration error: 'userIdAttribute' not a string literal"
                );
            }
            $this->userIdAttribute = $config['userIdAttribute'];
        }

        if (array_key_exists('blacklist', $config)) {
            if (!is_array($config['blacklist'])) {
                Logger::error(
                    "[attrauthvoms] Configuration error: 'blacklist' not an array"
                );
                throw new Error\Exception(
                    "attrauthvoms configuration error: 'blacklist' not an array"
                );
            }
            $this->blacklist = $config['blacklist'];
        }
        if (array_key_exists('voBlacklist', $config)) {
            if (!is_array($config['voBlacklist'])) {
                Logger::error(
                    "[attrauthcomanage] Configuration error: 'voBlacklist' not an array"
                );
                throw new Error\Exception(
                    "attrauthcomanage configuration error: 'voBlacklist' not an array"
                );
            }
            $this->voBlacklist = $config['voBlacklist'];
        }
    }

    public function process(&$state)
    {
        try {
            assert('is_array($state)');
            if (
                isset($state['SPMetadata']['entityid'])
                && in_array($state['SPMetadata']['entityid'], $this->blacklist, true)
            ) {
                Logger::debug(
                    "[attrauthvoms] process: Skipping blacklisted SP "
                    . var_export($state['SPMetadata']['entityid'], true)
                );
                return;
            }
            if (empty($state['Attributes'][$this->userIdAttribute])) {
                Logger::debug(
                    "[attrauthvoms] process: Skipping user with no '"
                    . var_export($this->userIdAttribute, true) . "' attribute"
                );
                return;
            }
            $userIds = $state['Attributes'][$this->userIdAttribute];
            foreach ($userIds as $userId) {
                $vos = $this->getVOs($userId);
                foreach ($vos as $vo) {
                    if (empty($vo['vo_id']) || in_array($vo['vo_id'], $this->voBlacklist, true)) {
                        continue;
                    }
                    $roles = ["member", "vm_operator"]; // TODO
                    if (empty($state['Attributes']['eduPersonEntitlement'])) {
                        $state['Attributes']['eduPersonEntitlement'] = [];
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
        Logger::debug("[attrauthvoms] getVOs: userId="
            . var_export($userId, true));

        $result = [];
        $db = Database::getInstance();
        $queryParams = [
            'subject' => [$userId, PDO::PARAM_STR],
        ];
        $stmt = $db->read($this->voQuery, $queryParams);
        if ($stmt->execute()) {
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $result[] = $row;
            }
            Logger::debug("[attrauthvoms] getVOs: result="
                . var_export($result, true));
            return $result;
        } else {
            throw new Error\Exception(
                'Failed to communicate with COmanage Registry: ' . var_export($db->getLastError(), true)
            );
        }

        return $result;
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
