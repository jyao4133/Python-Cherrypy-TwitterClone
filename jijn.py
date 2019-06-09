lists = [{'message': '@json.\xa0👌', 'sender_created_at': 'Sat Jun  8 21:04:39 2019', 'loginserver_record': 'jall229', 'signature': '8f1e2c8f39e3e575dd25dd5a7e1af1218fe7b8f4bda64af03812f4ec8ee16ebc360ba9ac4c9c1f617d5b5750ea40808a52b51b7e200eed0e9528e67df07f9a05'}, {'message': 'spam', 'sender_created_at': 'Sat Jun  8 21:53:43 2019', 'loginserver_record': 'ddhy609', 'signature': 'd1d1eec954493b96e651be0533bc249b35a463ef17dd377103085da583695e5b858792f30f6d4d137d3087fe049893ed9f2575233b67f2c4e7af8296db014d08'}, {'message': 'spammm', 'sender_created_at': 'Sat Jun  8 21:53:51 2019', 'loginserver_record': 'ddhy609', 'signature': '83c82e29c6fa49a24dba2302d29312e9917b4bdb626c776a6b128f0d2170a270a0ec4ad350696b07ac425168bd2baf637a6a9225df5f07cfd93dde0bc0656907'}]
people = ['somone', 'ddhy609']
temp = []

for person in people:
    for mess in lists:
        if (mess['loginserver_record'] == person):
            temp.append(mess)

l3 = [x for x in lists if x not in temp]



print (l3)