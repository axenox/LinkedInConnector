<?php
namespace axenox\LinkedInConnector\DataConnectors;

use exface\UrlDataConnector\DataConnectors\HttpConnector;
use Symfony\Component\DomCrawler\Crawler;
use GuzzleHttp\Psr7\Request;
use exface\Core\Interfaces\DataSources\DataQueryInterface;
use exface\Core\Exceptions\DataSources\DataQueryFailedError;
use GuzzleHttp\Exception\RequestException;
use exface\Core\Exceptions\Security\AuthenticationFailedError;
use exface\Core\Interfaces\Contexts\ContextManagerInterface;
use exface\UrlDataConnector\Interfaces\HttpConnectionInterface;
use exface\Core\Exceptions\DataSources\DataConnectionFailedError;
use axenox\LinkedInConnector\DataConnectors\Authentication\LinkedInVoyagerApiAuth;
use axenox\LinkedInConnector\DataConnectors\Authentication\LinkedInVoyagerApiAuthToken;
use exface\Core\CommonLogic\Security\AuthenticationToken\UsernamePasswordAuthToken;
use exface\Core\CommonLogic\UxonObject;
use GuzzleHttp\Exception\ClientException;

class LinkedInVoyagerApiConnector extends HttpConnector
{
    private $csrfToken = null;
    
    /**
     *
     * {@inheritDoc}
     * @see \exface\UrlDataConnector\DataConnectors\HttpConnector::performQuery()
     */
    protected function performQuery(DataQueryInterface $query)
    {
        $request = $query->getRequest();
        $request = $request->withHeader('csrf-token', $this->getCsrfToken());
        $request = $request->withHeader('accept', 'application/json');
        $request = $request->withHeader('x-li-lang', 'de_DE');
        $request = $request->withHeader('x-li-track', '{"clientVersion":"1.6.*","osName":"web","timezoneOffset":2,"deviceFormFactor":"DESKTOP","mpName":"voyager-web","displayDensity":1}');
        $query->setRequest($request);
        try {
            return parent::performQuery($query);
        } catch (DataQueryFailedError|AuthenticationFailedError $e) {
            $prev = $e->getPrevious();
            do {
                if ($prev instanceof ClientException) {
                    $er = $prev;
                    break;
                }
            } while ($prev = $prev->getPrevious());
        } catch (RequestException $er) {
            // do nothing, $er is there explicitly
        }
        
        if ($er && $er->getResponse() && $er->getResponse()->getStatusCode() == 403) {
            try {
                $this->loginToLinkedIn();
                return $this->performQuery($query);
            } catch (\Throwable $el) {
                // continue with default logic below
            }
        }
        throw ($e ?? $er ?? $el);
    }
    
    /**
     *
     * @return string
     */
    protected function getLoginUrl() : string
    {
        return 'https://www.linkedin.com/uas/login';
    }
    
    /**
     *
     * {@inheritDoc}
     * @see \exface\UrlDataConnector\DataConnectors\AbstractUrlConnector::getUrl()
     */
    public function getUrl()
    {
        return parent::getUrl() ?? 'https://www.linkedin.com/';
    }
    
    /**
     *
     * {@inheritDoc}
     * @see \exface\UrlDataConnector\DataConnectors\HttpConnector::getUseCookies()
     */
    public function getUseCookies() : bool
    {
        return true;
    }
    
    /**
     *
     * {@inheritDoc}
     * @see \exface\UrlDataConnector\DataConnectors\HttpConnector::getUseCookieSessions()
     */
    public function getUseCookieSessions() : bool
    {
        return true;
    }
    
    /**
     *
     * @return string
     */
    protected function getCsrfToken() : string
    {
        if ($this->csrfToken === null) {
            if ($token = $this->getWorkbench()->getApp('axenox.LinkedInConnector')->getContextVariable($this->getCsrfTokenContextVarName())) {
                $this->csrfToken = $token;
            } elseif ($token = $this->loginToLinkedIn()->getCsrfToken()) {
                $this->setCsrfToken($token);
            } else {
                throw new DataConnectionFailedError($this, 'Cannot get CSRF-token!');
            }
        }
        return $this->csrfToken;
    }
    
    /**
     *
     * @return string
     */
    protected function getCsrfTokenContextVarName() : string
    {
        return 'csrf_token';
    }
    
    /**
     *
     * @param string $value
     * @return HttpConnectionInterface
     */
    protected function setCsrfToken(string $value) : HttpConnectionInterface
    {
        $this->csrfToken = $value;
        $this->getWorkbench()->getApp('axenox.LinkedInConnector')->setContextVariable($this->getCsrfTokenContextVarName(), $value, ContextManagerInterface::CONTEXT_SCOPE_SESSION);
        return $this;
    }
    
    protected function loginToLinkedIn() : LinkedInVoyagerApiAuthToken
    {
        $provider = $this->getAuthProvider();
        if (! $provider->getUser() || ! $provider->getPassword()) {
            throw new AuthenticationFailedError($this, 'Please provide an email address and a password to log in to LinkedIn');
        }
        $this->resetCookies();
        return $provider->authenticate(new UsernamePasswordAuthToken($provider->getUser(), $provider->getPassword()));
    }
    
    /**
     *
     * {@inheritDoc}
     * @see \exface\UrlDataConnector\DataConnectors\HttpConnector::getAuthProviderConfig()
     */
    protected function getAuthProviderConfig() : ?UxonObject
    {
        return parent::getAuthProviderConfig() ?? new UxonObject([
            'class' => '\\' . LinkedInVoyagerApiAuth::class
        ]);
    }
    
    protected function hasAuthentication() : bool
    {
        return true;
    }
}