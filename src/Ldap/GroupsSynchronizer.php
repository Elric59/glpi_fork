<?php

/**
 * ---------------------------------------------------------------------
 *
 * GLPI - Gestionnaire Libre de Parc Informatique
 *
 * http://glpi-project.org
 *
 * @copyright 2015-2023 Teclib' and contributors.
 * @copyright 2003-2014 by the INDEPNET Development Team.
 * @licence   https://www.gnu.org/licenses/gpl-3.0.html
 *
 * ---------------------------------------------------------------------
 *
 * LICENSE
 *
 * This file is part of GLPI.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * ---------------------------------------------------------------------
 */

use Glpi\Toolbox\Sanitizer;


/**
 *  Class used to manage Auth LDAP Group
 */

class GroupsSynchronizer
{

    /**
     * Get the group's cn by giving his DN
     *
     * @param resource $ldap_connection ldap connection to use
     * @param string   $group_dn        the group's dn
     *
     * @return string the group cn
     */
    public static function getGroupSyncFieldByDn($ldap_connection, $group_dn, $syncfield)
    {

        $sr = @ldap_read($ldap_connection, $group_dn, "objectClass=*", [$syncfield]);
        if ($sr === false) {
            // 32 = LDAP_NO_SUCH_OBJECT => This error can be silented as it just means that search produces no result.
            if (ldap_errno($ldap_connection) !== 32) {
                trigger_error(
                    AuthLDAP::buildError(
                        $ldap_connection,
                        sprintf(
                            'Unable to get LDAP group having DN `%s`',
                            $group_dn
                        )
                    ),
                    E_USER_WARNING
                );
            }
            return false;
        }
        $v  = AuthLDAP::get_entries_clean($ldap_connection, $sr);
        if (!is_array($v) || (count($v) == 0) || empty($v[0][$syncfield])) {
            return false;
        }
        return AuthLDAP::getFieldValue($v[0], $syncfield);
        ;
    }

    /**
     * Does LDAP group already exists in the database?
     *
     * @param string  $name          User login/name
     * @param array $existing_dn   Existing DN in databse
     * @param ?string $sync          Sync field
     *
     *
     */
    public static function getLdapExistingGroup($name, $existing_dn, $sync = null): bool
    {
        global $DB;
        $group = new Group();

        if ($sync !== null && $group->getFromDBbySyncField($DB->escape($sync))) {
            return true;
        }

        if (isset($existing_dn[strtolower($name)])) {
            return true;
        }

        return false;
    }

    /**
     * Is synchronisation field used for current server
     *
     * @return boolean
     */
    public function isSyncFieldGroupUsed(): bool
    {
        if ($this->getID() <= 0) {
            return false;
        }
        $count = countElementsInTable(
            'glpi_groups',
            [
                'NOT'       => ['sync_field_group' => null]
            ]
        );
        return $count > 0;
    }

    /**
     * Get the list of LDAP group to add/synchronize
     * When importing, already existing groups will be filtered
     *
     * @param integer  $auths_id  ID of the server to use
     * @param string  $filter  ldap filter to use (default '')
     * @param string  $filter2 second ldap filter to use (which case?) (default '')
     * @param integer $entity  working entity
     * @param string  $order   display order (default DESC)
     * @param array   $results       result stats
     * @param boolean $limitexceeded limit exceeded exception
     *
     * @return array
     */
    public static function getGroups(
        $auths_id,
        $filter,
        $filter2,
        $entity,
        &$limitexceeded,
        $order = 'DESC'
    ) {
        global $DB;

        $ldap_groups    = AuthLDAP::getAllGroups(
            $auths_id,
            $filter,
            $filter2,
            $entity,
            $limitexceeded,
            $order
        );

        $config_ldap   = new AuthLDAP();
        $config_ldap->getFromDB($auths_id);

        if (!is_array($ldap_groups) || count($ldap_groups) == 0) {
            return $ldap_groups;
        }


        $sync_field = $config_ldap->isSyncFieldGroupEnabled() ? $config_ldap->fields['sync_field_group'] : null;
        $glpi_groups = [];
        //Get all groups from GLPI DB for the current entity and the subentities
        $iterator = $DB->request([
            'SELECT' => ['ldap_group_dn','ldap_value'],
            'FROM'   => 'glpi_groups',
            'WHERE'  => getEntitiesRestrictCriteria('glpi_groups')
        ]);

        //If the group exists in DB -> unset it from the LDAP groups
        foreach ($iterator as $group) {
            //use DN for next step
            //depending on the type of search when groups are imported
            //the DN may be in two separate fields
            if (isset($group["ldap_group_dn"]) && !empty($group["ldap_group_dn"])) {
                $glpi_groups[strtolower($group["ldap_group_dn"])] = 1;
            } else if (isset($group["ldap_value"]) && !empty($group["ldap_value"])) {
                $glpi_groups[$group["ldap_value"]] = 1;
            }
        }
        $groups = [];
        $ligne = 0;
        foreach ($ldap_groups as $groupinfos) {
            $groups_to_add = [];
            $group = new Group();

            $group_sync_field = $config_ldap->isSyncFieldGroupEnabled() && isset($groupinfos[$sync_field])
                ? AuthLDAP::getFieldValue($groupinfos, $sync_field)
                : null;

            $group = self::getLdapExistingGroup(
                $groupinfos['dn'],
                $glpi_groups,
                $group_sync_field
            );
            if (!$_SESSION["ldap_group_mode"] && $group  || $_SESSION["ldap_group_mode"] && !$group) {
                continue;
            }


            $groups[$ligne]["dn"]          = $groupinfos['dn'];
            $groups[$ligne]["cn"]          = $groupinfos["cn"];
            $groups[$ligne]["search_type"] = $groupinfos["search_type"];
            if (!is_null($group_sync_field)) {
                $groups[$ligne]["sync_field_group"] = $group_sync_field;
            }
            $ligne++;
        }

        return $groups;
    }

    public function updateLdapGroupDn($group, $group_infos, $syncfield, $options)
    {
        return $group->update(Sanitizer::sanitize([
            "id"               => $group->getID(),

            "ldap_group_dn"    => $group_infos["dn"],
            "sync_field_group" => $syncfield,
            "entities_id"      => $options['entities_id'],
            "is_recursive"     => $options['is_recursive']
        ]));
    }

    public function updateLdapField($group, $config_ldap, $group_infos, $syncfield, $options)
    {
        return $group->update(Sanitizer::sanitize([
            "id"               => $group->getID(),

            "ldap_field"       => $config_ldap->fields["group_field"],
            "ldap_value"       => $group_infos["dn"],
            "sync_field_group" => $syncfield,
            "entities_id"      => $options['entities_id'],
            "is_recursive"     => $options['is_recursive']
        ]));
    }

    public function addLdapGroupDn($group, $group_infos, $syncfield, $options)
    {
        return $group->add(Sanitizer::sanitize([
            "name"             => $group_infos["cn"][0],
            "ldap_group_dn"    => $group_infos["dn"],
            "sync_field_group" => $syncfield,
            "entities_id"      => $options['entities_id'],
            "is_recursive"     => $options['is_recursive'],
            "is_assign"        => 0,
            "is_task"          => 0,
            "is_notify"        => 0,
            "is_manager"       => 0,
        ]));
    }


}