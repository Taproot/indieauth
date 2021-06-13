rm -rf docs/coverage/
XDEBUG_MODE=coverage  ./vendor/bin/phpunit tests --coverage-filter src --coverage-html docs/coverage
mv docs/coverage/_css docs/coverage/phpunit_css
mv docs/coverage/_icons docs/coverage/phpunit_icons
mv docs/coverage/_js docs/coverage/phpunit_js
grep -rl _css docs/coverage | xargs sed -i "" -e 's/_css/phpunit_css/g'
grep -rl _icons docs/coverage | xargs sed -i "" -e 's/_icons/phpunit_icons/g'
grep -rl _js docs/coverage | xargs sed -i "" -e 's/_js/phpunit_js/g'