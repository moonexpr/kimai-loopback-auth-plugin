<?php

/*
 * Appends the LoopbackAuthenticator to the secured_area firewall's
 * authenticator manager.
 *
 * Symfony refuses to let a plugin add firewall config in a second file, so we
 * reach the authenticator chain at the container level instead: the firewall's
 * AuthenticatorManager receives its authenticators as constructor argument 0
 * (an IteratorArgument of service references). We append our authenticator's
 * reference there. SecurityExtension has already created this definition by
 * the time compiler passes run, so the append is safe.
 *
 * This is the one Symfony-internal coupling in the plugin: if a future Symfony
 * release changes the manager's service id or argument shape, this pass needs
 * a tweak. It fails safe — if the definition or argument isn't found, it
 * no-ops and the firewall simply lacks loopback auth (normal login still works).
 */

namespace KimaiPlugin\LoopbackAuthBundle\DependencyInjection\Compiler;

use KimaiPlugin\LoopbackAuthBundle\Security\LoopbackAuthenticator;
use Symfony\Component\DependencyInjection\Argument\IteratorArgument;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

final class RegisterLoopbackAuthenticatorPass implements CompilerPassInterface
{
    private const FIREWALL = 'secured_area';

    public function process(ContainerBuilder $container): void
    {
        $managerId = 'security.authenticator.manager.' . self::FIREWALL;
        if (!$container->hasDefinition($managerId)) {
            return;
        }
        if (!$container->hasDefinition(LoopbackAuthenticator::class)) {
            return;
        }

        $manager = $container->getDefinition($managerId);
        $authenticators = $manager->getArgument(0);
        $reference = new Reference(LoopbackAuthenticator::class);

        if ($authenticators instanceof IteratorArgument) {
            $values = $authenticators->getValues();
            $values[] = $reference;
            $authenticators->setValues($values);
            $manager->replaceArgument(0, $authenticators);

            return;
        }

        if (\is_array($authenticators)) {
            $authenticators[] = $reference;
            $manager->replaceArgument(0, $authenticators);
        }
    }
}
