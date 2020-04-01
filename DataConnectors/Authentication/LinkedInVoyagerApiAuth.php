<?php
namespace axenox\LinkedInConnector\DataConnectors\Authentication;

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
use exface\UrlDataConnector\DataConnectors\Authentication\HttpBasicAuth;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;
use exface\Core\CommonLogic\Security\AuthenticationToken\UsernamePasswordAuthToken;
use GuzzleHttp\Client;

class LinkedInVoyagerApiAuth extends HttpBasicAuth
{
    protected function getAuthenticationUrl() : ?string
    {
        return parent::getAuthenticationUrl() ?? 'https://www.linkedin.com/uas/login';
    }
    
    public function authenticate(AuthenticationTokenInterface $token) : AuthenticationTokenInterface
    {
        if (! $token instanceof UsernamePasswordAuthToken) {
            throw new AuthenticationFailedError($this, 'Invalid authentication token type "' . get_class($token) . '" for LinkedIn Voyager API authentication!');
        }
        $csrfToken = $this->loginToLinkedIn($token->getUsername(), $token->getPassword());
        return new LinkedInVoyagerApiAuthToken($token->getUsername(), $token->getPassword(), $csrfToken, $token->getFacade());
    }
    
    /**
     * Returns the CSRF token
     * @return string|NULL
     */
    protected function loginToLinkedIn(string $user, string $password) : ?string
    {
        $loginUrl = $this->getAuthenticationUrl();
        $loginResponse = $this->getDataConnection()->sendRequest(new Request('GET', $loginUrl));
        $crawler = new Crawler($loginResponse->getBody()->__toString(), $loginUrl);
        
        $formNode = $crawler->filter('.login__form');
        if ($formNode->count() === 0) {
            return null;
        }
        $form = $formNode->form();
        $data = $form->getPhpValues();
        $data['session_key'] = $user;
        $data['session_password'] = $password;
        
        $method = $form->getMethod();
        $uri = $form->getUri();
        $headers = [
            'Content-Type' => 'application/x-www-form-urlencoded'
        ];
        $body = http_build_query($data, '', '&');
        $resultRequest = new Request($method, $uri, $headers, $body);
        $resultResponse = $this->getDataConnection()->sendRequest($resultRequest);
        
        if ($resultResponse->getStatusCode() == 401) {
            throw new AuthenticationFailedError($this, 'LinkedIn authentication failed!');
        }
        
        $resultCrawler = new Crawler($resultResponse->getBody()->__toString());
        $errorNode = $crawler->filter('#error-for-password');
        if ($errorNode && $errorNode->text()) {
            throw new AuthenticationFailedError($this, 'LinkedIn authentication failed: ' . $crawler->filter('#error-for-password')->html());
        }
        
        return $data['csrfToken'];
    }
}