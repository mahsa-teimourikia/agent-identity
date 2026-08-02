POLICY={'reader':{'ticket:read'},'agent':{'ticket:read','ticket:comment'}}
def decide(role,action,approved=False):
    if action=='ticket:delete' and not approved:return False,'approval required'
    return (True,'allowed') if action in POLICY.get(role,set()) else (False,'denied')
if __name__=='__main__':
    assert decide('agent','ticket:comment')[0] and not decide('reader','ticket:comment')[0] and not decide('agent','ticket:delete')[0]
    print('PASS: deny-by-default authorization')
