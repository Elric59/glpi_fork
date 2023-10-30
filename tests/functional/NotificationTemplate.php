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

namespace tests\units;

use DbTestCase;

/* Test for inc/notificationtemplate.class.php */

class NotificationTemplate extends DbTestCase
{
    public function testClone()
    {
        global $DB;

        $iterator = $DB->request([
            'SELECT' => 'notificationtemplates_id',
            'FROM'   => \NotificationTemplateTranslation::getTable(),
            'LIMIT'  => 1
        ]);

        $data = $iterator->current();
        $template = new \NotificationTemplate();
        $template->getFromDB($data['notificationtemplates_id']);
        $added = $template->clone();
        $this->integer((int)$added)->isGreaterThan(0);

        $clonedTemplate = new \NotificationTemplate();
        $this->boolean($clonedTemplate->getFromDB($added))->isTrue();

        unset($template->fields['id']);
        unset($template->fields['name']);
        unset($template->fields['date_creation']);
        unset($template->fields['date_mod']);

        unset($clonedTemplate->fields['id']);
        unset($clonedTemplate->fields['name']);
        unset($clonedTemplate->fields['date_creation']);
        unset($clonedTemplate->fields['date_mod']);

        $this->array($template->fields)->isIdenticalTo($clonedTemplate->fields);
    }

    protected function linksProvider(): iterable
    {
        $base_url = GLPI_URI;

        yield [
            'content' => <<<HTML
Relative link from GLPI: <a href="/">GLPI index</a>
HTML,
            'expected' => <<<HTML
Relative link from GLPI: <a href="{$base_url}/">GLPI index</a>
HTML,
        ];

        yield [
            'content' => <<<HTML
Relative link from GLPI: <a href="/front/computer.php?id=2" title="Computer 2">Computer</a>
HTML,
            'expected' => <<<HTML
Relative link from GLPI: <a href="{$base_url}/front/computer.php?id=2" title="Computer 2">Computer</a>
HTML,
        ];

        yield [
            'content' => <<<HTML
Absolute link from GLPI: <a href="{$base_url}/front/computer.php?id=2" title="Computer 2">Computer</a>
HTML,
            'expected' => <<<HTML
Absolute link from GLPI: <a href="{$base_url}/front/computer.php?id=2" title="Computer 2">Computer</a>
HTML,
        ];

        yield [
            'content' => <<<HTML
External link from GLPI: <a href="https://faq.teclib.com/01_getting_started/getting_started/" title="Faq">Faq</a>
HTML,
            'expected' => <<<HTML
External link from GLPI: <a href="https://faq.teclib.com/01_getting_started/getting_started/" title="Faq">Faq</a>
HTML,
        ];

        yield [
            'content' => <<<HTML
External link without protocol from GLPI: <a href="//faq.teclib.com/01_getting_started/getting_started/" title="Faq">Faq</a>
HTML,
            'expected' => <<<HTML
External link without protocol from GLPI: <a href="//faq.teclib.com/01_getting_started/getting_started/" title="Faq">Faq</a>
HTML,
        ];
    }

    /**
     * @dataProvider linksProvider
     */
    public function testConvertRelativeGlpiLinksToAbsolute(
        string $content,
        string $expected
    ): void {
        $instance = $this->newTestedInstance();
        $result = $this->callPrivateMethod($instance, 'convertRelativeGlpiLinksToAbsolute', $content);
        $this->string($result)->isEqualTo($expected);
    }
}
