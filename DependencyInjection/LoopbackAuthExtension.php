<?php

/*
 * DI extension for LoopbackAuthBundle.
 *
 * Symfony hard-forbids defining firewall config across more than one file
 * ("You are not allowed to define new elements for path security.firewalls"),
 * so a plugin cannot inject a `remote_user` authenticator via config prepend.
 * Instead this extension registers the loopback authenticator as a service
 * (Resources/config/services.yaml); RegisterLoopbackAuthenticatorPass then
 * appends it to the secured_area firewall's authenticator manager at compile
 * time — see Security/LoopbackAuthenticator and the compiler pass.
 */

namespace KimaiPlugin\LoopbackAuthBundle\DependencyInjection;

use App\Plugin\AbstractPluginExtension;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

final class LoopbackAuthExtension extends AbstractPluginExtension
{
    public function load(array $configs, ContainerBuilder $container): void
    {
        $loader = new YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load('services.yaml');
    }
}
