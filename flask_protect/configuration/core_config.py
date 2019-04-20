__DEFAULT_CORE_CONFIG = {
    #Basic Functionality
    'BLUEPRINT_NAME': 'protect',
    'URL_PREFIX':None,
    'SUBDOMAIN':None,
    'FLASH_MESSAGES': True,
    'URLS': {
        'LOGIN_URL':'/login',
        'LOGOUT_URL':'/logout',
        'REGISTER_URL':'/register',
        'RESET_PASS_URL':'/reset',
        'CHANGE_PASS_URL':'/change',
        'CONFIRM_EMAIL_URL':'/confirm'
        },
    'TEMPLATES': {
        'LOGIN_TEMPLATE': 'protect/login_user.html',
        'REGISTER_TEMPLATE': 'protect/register_user.html',
        'RESET_PASS_TEMPLATE': 'protect/reset_password.html',
        'FORGOT_PASS_TEMPLATE': 'protect/forgot_password.html',
        'CHANGE_PASS_TEMPLATE': 'protect/change_password.html',
        'SEND_CONFIRM_TEMPLATE': 'protect/send_confirmation.html',
    }
    
}
