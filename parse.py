import ast
import csv
import matplotlib.pyplot as plt

if __name__ == "__main__":
    with open("table_4.csv", "r") as csvfile:
        reader = csv.reader(csvfile, delimiter=",")

        url_to_icw = {}
        for row in reader:
            url_to_icw[row[0]] = []
            for i in range(1, len(row)):
                state, icw = ast.literal_eval(row[i])
                url_to_icw[row[0]].append((state, icw))

        url_to_icw_size = {}
        for url in url_to_icw:
            result = url_to_icw[url]

            # First count the number of success
            cnt = 0
            success_to_cnt = {}
            for state, icw in result:
                if state == "SUCCESS" or state == "MSSLARGE":
                    success_to_cnt[icw] = success_to_cnt.get(icw, 0) + 1
                    cnt += 1
            if cnt >= 3:
                icw = next(iter(success_to_cnt))
                if success_to_cnt[icw] == cnt:
                    url_to_icw_size[url] = icw / 64

        print url_to_icw_size

        # Now aggregate the result.
        table = [0, 0, 0, 0, 0]
        icws = []
        for url in url_to_icw_size:
            size = url_to_icw_size[url]
            if 1 <= size <= 4:
                table[size - 1] += 1
            elif size >= 5:
                table[4] += 1

            if size > 0:
                icws.append(size)

        print table

        fig, ax = plt.subplots()
        n, bins, patches = ax.hist(
            icws,
            48,
            log=True,
            density=False,
            facecolor='g',
            alpha=0.75,
            range=[1, 56])

        plt.xlabel('Window Size')
        plt.ylabel('Number of Servers (Log)')
        plt.title('Initial Congestion Window Size of Servers (HTTPS)')
        plt.grid(True)

        ax.annotate(
            "ICW 4",
            xy=(4, 603),
            xycoords='data',
            xytext=(4, 1000),
            textcoords='data',
            arrowprops=dict(arrowstyle="->", connectionstyle="arc3"))

        plt.savefig("icw.png")
