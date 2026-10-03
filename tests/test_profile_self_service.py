import unittest
from unittest.mock import patch
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.sql import visitors
from sqlalchemy.sql.elements import BindParameter
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

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
            async def execute(self, statement, *args, **kwargs):
                # PostgreSQL accepts UUID strings; SQLite's UUID adapter needs UUID objects.
                def normalize(node):
                    if isinstance(node, BindParameter) and isinstance(node.value, str) and node.type.python_type is UUID:
                        return BindParameter(node.key, UUID(node.value), type_=node.type)
                statement = visitors.replacement_traverse(statement, {}, normalize)
                return db.execute(statement, *args, **kwargs)
            async def commit(self): db.commit()
            async def refresh(self, row): db.refresh(row)
        async def dependency(): yield Adapter()
        self.main.app.dependency_overrides[self.main.get_session] = dependency
        self.claims = {'sub': str(self.member_id), 'actor_type': 'website_user', 'website_id': str(self.site_id)}
        self.decode = patch.object(self.main, 'safe_decode_token', side_effect=lambda _: self.claims)
        self.decode.start()
        self.client = TestClient(self.main.app)

    def tearDown(self):
        self.client.close()
        self.decode.stop()
        self.main.app.dependency_overrides.clear()
        self.db.close()
        self.engine.dispose()

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

    def test_owner_save_still_targets_owner(self):
        self.claims = {'sub': str(self.member_id)}
        response = self.save({'full_name': 'Updated owner', 'display_name': 'Owner name'})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['full_name'], 'Updated owner')
        self.assertEqual(self.db.get(self.WebsiteUser, self.member_id).full_name, 'Member')


if __name__ == '__main__': unittest.main()
