<?php
namespace axenox\LinkedInConnector\DataConnectors\Authentication;

use exface\Core\CommonLogic\Security\AuthenticationToken\UsernamePasswordAuthToken;
use exface\Core\Interfaces\Facades\FacadeInterface;

class LinkedInVoyagerApiAuthToken extends UsernamePasswordAuthToken
{
    private $csrfToken = null;
    
    public function __construct(string $username, string $password, string $csrfToken = null, FacadeInterface $facade = null)
    {
        parent::__construct($username, $password, $facade);
        $this->csrfToken = $csrfToken;
    }
    
    public function getCsrfToken() : ?string
    {
        return $this->csrfToken;
    }
}