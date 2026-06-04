<?php

/*
 * LoopbackAuthBundle — a Kimai plugin that enables passwordless auto-login
 * for requests originating from the same machine (loopback).
 *
 * It contains no credential logic of its own: a self-validating authenticator
 * (Security/LoopbackAuthenticator) trusts the REMOTE_USER FastCGI param, which
 * the web server (nginx) sets ONLY for loopback clients — see the project's
 * servers/kimai.conf. Because Symfony forbids a plugin from adding firewall
 * config, the authenticator is wired into Kimai's secured_area firewall at the
 * container level by RegisterLoopbackAuthenticatorPass (registered in build()).
 *
 * Nothing here touches Kimai core files, so the whole feature survives upgrades.
 */

namespace KimaiPlugin\LoopbackAuthBundle;

use App\Plugin\PluginInterface;
use KimaiPlugin\LoopbackAuthBundle\DependencyInjection\Compiler\RegisterLoopbackAuthenticatorPass;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

final class LoopbackAuthBundle extends Bundle implements PluginInterface
{
    public function build(ContainerBuilder $container): void
    {
        parent::build($container);

        $container->addCompilerPass(new RegisterLoopbackAuthenticatorPass());
    }
}
