import unittest
from unittest.mock import patch
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.sql import visitors
from sqlalchemy.sql.elements import BindParameter
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import JSONB

@compiles(JSONB, "sqlite")
def compile_jsonb_sqlite(type_, compiler, **kwargs):
    return "JSON"

from test_smoke import _load_main_module


class ProfileSelfServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = _load_main_module()

    def setUp(self):
        from models import Base, User, Website, WebsiteUser
        self.User, self.WebsiteUser = User, WebsiteUser
        self.engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.member_id, self.site_id, self.other_id = uuid4(), uuid4(), uuid4()
        self.db = Session(self.engine, expire_on_commit=False)
        self.db.add(User(id=self.member_id, email='same@example.com', full_name='Owner', identity_data={}))
        self.db.add(Website(id=self.site_id, owner_id=self.member_id, name='Site', slug='site'))
        self.db.add(Website(id=self.other_id, owner_id=self.member_id, name='Other', slug='other'))
        self.db.add(WebsiteUser(id=self.member_id, website_id=self.site_id, email='same@example.com', full_name='Member', identity_data={'bio': 'Keep me', 'roles': ['member']}))
        self.db.commit()
        db = self.db
        class Adapter:
            def add(self, row): db.add(row)
            async def execute(self, statement, *args, **kwargs):
                # PostgreSQL accepts UUID strings; SQLite's UUID adapter needs UUID objects.
                def normalize(node):
                    if isinstance(node, BindParameter) and isinstance(node.value, str) and isinstance(node.type, __import__('sqlalchemy').types.Uuid):
                        return BindParameter(node.key, UUID(node.value), type_=node.type)
                statement = visitors.replacement_traverse(statement, {}, normalize)
                return db.execute(statement, *args, **kwargs)
            async def commit(self): db.commit()
            async def rollback(self): db.rollback()
            async def refresh(self, row): db.refresh(row)
        async def dependency(): yield Adapter()
        self.main.app.dependency_overrides[self.main.get_session] = dependency
        self.claims = {'sub': str(self.member_id), 'actor_type': 'website_user', 'website_id': str(self.site_id)}
        self.decode = patch.object(self.main, 'safe_decode_token', side_effect=lambda _: self.claims)
        self.decoder = self.decode.start()
        self.client = TestClient(self.main.app)

    def tearDown(self):
        self.client.close()
        self.decode.stop()
        self.main.app.dependency_overrides.clear()
        self.db.close()
        self.engine.dispose()

    def test_verified_provider_shares_canonical_user_identity_only(self):
        owner = self.db.get(self.User, self.member_id)
        member = self.db.get(self.WebsiteUser, self.member_id)
        owner.provider = member.provider = "google"
        owner.provider_account_id = member.provider_account_id = "verified-sub"
        new_member_id = uuid4()
        member.id = new_member_id
        self.claims["sub"] = str(new_member_id)
        from models import AccountIdentityLink
        self.db.add(AccountIdentityLink(subject=f'website:{self.site_id}:{new_member_id}', canonical_user_id=self.member_id,
            website_id=self.site_id,website_user_id=new_member_id,linked_at='2026-10-05'))
        self.db.commit()
        response = self.client.get('/auth/me', headers={'Authorization': 'Bearer local-test'})
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertEqual(data['id'], str(self.member_id))
        self.assertEqual(data['account_id'],str(new_member_id))
        self.assertEqual(data['canonical_user_id'], str(self.member_id))
        self.assertFalse(data['is_sysadmin'])
        owner.identity_data = {'roles': ['owner'], 'theme_mode': 'dark', 'avatar_url': 'https://example.com/owner.png'}
        self.db.commit()
        response = self.client.get('/auth/me', headers={'Authorization': 'Bearer local-test'})
        self.assertEqual(response.json()['identity_data']['theme_mode'], 'dark')
        self.assertEqual(response.json()['identity_data']['roles'], ['member'])
        response = self.save({'full_name': 'Shared name', 'avatar_url': 'https://example.com/shared.png',
                              'theme_mode': 'light', 'roles': ['admin'], 'is_sysadmin': True,
                              'canonical_user_id': str(uuid4()), 'provider_account_id': 'other'})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['id'], str(self.member_id))
        self.assertEqual(response.json()['identity_data']['roles'], ['member'])
        self.assertEqual(owner.full_name, 'Shared name')
        self.assertEqual(owner.identity_data['theme_mode'], 'light')
        self.assertEqual(owner.identity_data['avatar_url'], 'https://example.com/shared.png')
        self.assertEqual(owner.identity_data['roles'], ['owner'])
        self.assertEqual(owner.provider_account_id, 'verified-sub')
        self.claims = {'sub': str(self.member_id), 'actor_type': 'owner'}
        response = self.save({'full_name': 'Owner edit', 'theme_mode': 'dark'})
        self.assertEqual(response.status_code, 200)
        self.claims = {'sub': str(new_member_id), 'actor_type': 'website_user', 'website_id': str(self.site_id)}
        response = self.client.get('/auth/me', headers={'Authorization': 'Bearer local-test'})
        self.assertEqual(response.json()['full_name'], 'Owner edit')
        self.assertEqual(response.json()['identity_data']['theme_mode'], 'dark')
        self.assertEqual(self.save({'theme_mode': 'invalid'}).status_code, 422)
        member.provider_account_id = "different-sub"
        member.identity_data = {"sub": "verified-sub", "canonical_user_id": str(self.member_id)}
        self.db.commit()
        response = self.client.get('/auth/me', headers={'Authorization': 'Bearer local-test'})
        self.assertEqual(response.json()['canonical_user_id'], str(self.member_id))
        member.provider_account_id = "verified-sub"
        member.provider = "github"
        self.db.commit()
        response = self.client.get('/auth/me', headers={'Authorization': 'Bearer local-test'})
        self.assertEqual(response.json()['canonical_user_id'], str(self.member_id))
        member.provider = "google"
        owner.is_active = False
        self.db.commit()
        response = self.client.get('/auth/me', headers={'Authorization': 'Bearer local-test'})
        self.assertEqual(response.status_code,401)

    def test_browser_account_link_requires_both_sessions_and_same_browser(self):
        import time
        import account_link_browser
        member = self.db.get(self.WebsiteUser, self.member_id)
        secondary_id = uuid4()
        member.id = secondary_id
        self.db.commit()
        primary = {'sub': str(self.member_id), 'actor_type': 'owner', 'exp': int(time.time())+600}
        secondary = {'sub': str(secondary_id), 'actor_type': 'website_user', 'website_id': str(self.site_id), 'exp': int(time.time())+600}
        self.decoder.side_effect = lambda token: primary if token == 'primary' else secondary
        with patch.object(account_link_browser, 'safe_decode_token', return_value=primary):
            browser = TestClient(self.main.app, base_url='https://id.example')
            try:
                browser.cookies.set('pidp_token', 'primary')
                review = browser.get('/auth/account-links/connect?app=site')
                self.assertEqual(review.status_code, 200, review.text)
                self.assertEqual(browser.post('/auth/account-links/connect?app=site', headers={'Origin': 'https://evil.example'}).status_code,403)
                start = browser.post('/auth/account-links/connect?app=site', headers={'Origin': 'https://id.example'}, follow_redirects=False)
                self.assertEqual(start.status_code,303,start.text)
                self.assertIn('app=site',start.headers['location'])
                self.assertIn('HttpOnly',start.headers['set-cookie'])
                self.assertIn('Secure',start.headers['set-cookie'])
                self.assertNotIn('primary',start.headers['location'])
                browser.cookies.set('pidp_token', 'secondary')
                self.assertEqual(browser.post('/auth/account-links/complete',headers={'Origin':'https://id.example'}).status_code,409)
                review = browser.get('/auth/account-links/finish')
                self.assertEqual(review.status_code,200,review.text)
                self.assertIn('Link these accounts',review.text)
                self.assertEqual(browser.post('/auth/account-links/complete',headers={'Origin':'https://evil.example'}).status_code,403)
                complete = browser.post('/auth/account-links/complete',headers={'Origin':'https://id.example'})
                self.assertEqual(complete.status_code,200,complete.text)
                self.assertEqual(browser.get('/auth/me',headers={'Authorization':'Bearer secondary'}).json()['id'],str(self.member_id))
                self.assertNotEqual(browser.post('/auth/account-links/complete',headers={'Origin':'https://id.example'}).status_code,200)
            finally:
                browser.close()

    def test_account_link_api_requires_proofs_and_a_one_use_preview(self):
        member = self.db.get(self.WebsiteUser, self.member_id)
        secondary_id = uuid4()
        member.id = secondary_id
        self.db.commit()
        primary = {'sub':str(self.member_id),'actor_type':'owner'}
        secondary = {'sub':str(secondary_id),'actor_type':'website_user','website_id':str(self.site_id)}
        self.decoder.side_effect = lambda token: primary if token == 'primary' else secondary
        headers = {'Authorization':'Bearer primary'}
        self.assertEqual(self.client.post('/auth/account-links/preview',headers=headers,json={}).status_code,400)
        plan = self.client.post('/auth/account-links/preview',headers=headers,json={'member_token':'secondary'})
        self.assertEqual(plan.status_code,200,plan.text)
        payload = {'member_token':'secondary','previewId':plan.json()['previewId'],'confirm':True}
        response = self.client.post('/auth/account-links/apply',headers=headers,json=payload)
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()['canonical_user_id'],str(self.member_id))
        self.assertEqual(self.client.post('/auth/account-links/apply',headers=headers,json=payload).status_code,409)

    def test_token_set_download_is_owner_scoped_and_stores_only_hashes(self):
        from models import UserAPIToken
        from sqlalchemy import select
        self.claims = {'sub': str(self.member_id), 'actor_type': 'owner'}
        response = self.client.post('/auth/tokens/download', headers={'Authorization': 'Bearer local-test'})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        self.assertIn('.env.pidp', response.headers['content-disposition'])
        values = dict(line.split('=', 1) for line in response.text.splitlines())
        self.assertEqual(set(values), {'PIDP_PAT', 'PIDP_ORG_PORTAL_TOKEN', 'PIDP_ORG_MCP_TOKEN', 'PIDP_ORG_ADMIN_TOKEN'})
        rows = self.db.execute(select(UserAPIToken)).scalars().all()
        self.assertEqual(len(rows), 4)
        self.assertEqual({row.scope for row in rows}, {'service', 'org_portal', 'org_mcp', 'org_admin'})
        for row in rows:
            self.assertEqual(row.owner_id, self.member_id)
            self.assertNotIn(row.token_hash, values.values())
        again = self.client.post('/auth/tokens/download', headers={'Authorization': 'Bearer local-test'})
        self.assertEqual(again.status_code, 200)
        self.assertNotEqual(again.text, response.text)

    def test_website_member_cannot_download_owner_token_set(self):
        response = self.client.post('/auth/tokens/download', headers={'Authorization': 'Bearer local-test'})
        self.assertEqual(response.status_code, 403)

    def save(self, payload):
        return self.client.put('/auth/me', headers={'Authorization': 'Bearer local-test'}, json=payload)

    def test_member_can_save_profile_without_owner_privileges(self):
        response = self.save({'full_name': 'New Name', 'display_name': 'New Name', 'avatar_url': 'https://example.test/avatar.png',
                              'id': str(uuid4()), 'website_id': str(self.other_id), 'email': 'admin@example.test', 'is_active': False,
                              'is_sysadmin': True, 'roles': ['admin']})
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertEqual(data['full_name'], 'New Name')
        self.assertFalse(data['is_sysadmin'])
        self.assertTrue(data['is_active'])
        self.assertEqual(data['email'], 'same@example.com')
        self.assertEqual(data['identity_data'], {'bio': 'Keep me', 'roles': ['member'], 'display_name': 'New Name', 'avatar_url': 'https://example.test/avatar.png'})
        self.assertEqual(self.db.get(self.User, self.member_id).full_name, 'Owner')
        denied = self.client.get('/websites', headers={'Authorization': 'Bearer local-test'})
        self.assertEqual(denied.status_code, 403)

    def test_wrong_or_missing_namespace_cannot_save(self):
        for website_id in [str(self.other_id), None]:
            self.claims['website_id'] = website_id
            self.assertIn(self.save({'full_name': 'No'}).status_code, [401, 404])
        self.assertEqual(self.db.get(self.WebsiteUser, self.member_id).full_name, 'Member')

    def test_admin_authority_uses_owner_ids_and_preserves_namespace(self):
        owner = self.db.get(self.User, self.member_id)
        owner.identity_data = {'roles': ['admin'], 'is_sysadmin': True}
        with patch.object(self.main, 'settings') as config:
            config.admin_user_ids_list = []
            config.admin_emails_list = ['same@example.com']
            self.assertFalse(self.main._is_pidp_sysadmin(owner))
            config.admin_user_ids_list = [str(self.member_id)]
            self.assertTrue(self.main._is_pidp_sysadmin(owner))
            member = self.db.get(self.WebsiteUser, self.member_id)
            self.assertFalse(self.main._to_user_public_from_website_user(member).is_sysadmin)

    def test_owner_save_still_targets_owner(self):
        self.claims = {'sub': str(self.member_id)}
        response = self.save({'full_name': 'Updated owner', 'display_name': 'Owner name'})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['full_name'], 'Updated owner')
        self.assertEqual(self.db.get(self.WebsiteUser, self.member_id).full_name, 'Member')


if __name__ == '__main__': unittest.main()
