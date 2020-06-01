import math

POINTS = {0: {'place': 'FIRST', 'value': 100}, 1: {'place': 'SECOND','value': 40}, 2: {'place': 'THIRD','value': 30}, 3: {'place': 'FOURTH','value': 0}}

def next_level(level):
	exponent = 1.5
	baseXP = 1000
	return math.floor(baseXP * (level ** exponent))

def add_points(db, user_id, points):
	pass
	'''
		Call db to add points
	'''

	#db.update_xp(points, user_id)

def get_level(points):
	levels = 1
	level = levels
	while points > next_level(levels):
		level = levels
		levels += 1
	
	return level

def distribute_points(results_dic):
	'''
		results_dic = {'player_sid_1': 60, 'player_sid_2': 40, 'player_sid_3': 100, 'player_sid_4': 30}
		results_dic = {'user_id_1': 60, 'user_id_2': 40, 'user_id_3': 100, 'user_id_4': 30}
	'''
	for i,u in enumerate(sorted(results_dic, key=lambda k: results_dic[k])):
		add_points(sorted_list[i], POINTS[i]['value'])

'''
print("XP points: 22000, level: ", end="")
print(get_level(22000))
print(get_level(0))

for n in range(1,21):
	print("Level {}, next level starts at {} points".format(n, next_level(n)))
'''
